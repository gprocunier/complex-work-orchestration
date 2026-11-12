"""Offline fact-data regressions; synthetic fixtures confer no pin qualification."""

from __future__ import annotations

import copy
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import codex_protocol_pin as pins, policy  # noqa: E402

REQUIRED = {
    "enum-includes": ("values",),
    "method-params-exclude": ("method", "forbidden_required"),
    "methods-equal": ("values",),
    "methods-include": ("values",),
    "param-property-enum": ("property", "definition", "values", "default"),
    "properties-absent": ("names",),
    "properties-present": ("names",),
    "property-description-contains": ("property", "text"),
    "required-includes": ("names",),
    "response-decision-union": ("bundle", "method", "decision_field", "strings", "objects"),
    "responses-present": ("bundle",),
}
ARRAY_FIELDS = {"values", "names", "strings", "forbidden_required"}
BAD_STRING = (None, False, 0, [], {})


@contextmanager
def copied_policy():
    with tempfile.TemporaryDirectory() as directory:
        policy_dir = Path(directory) / "policy"
        policy_dir.mkdir()
        target = policy_dir / "codex-protocol-pins.yaml"
        shutil.copyfile(ROOT / "policy" / target.name, target)
        policy.clear_policy_cache()
        try:
            with patch.object(policy, "POLICY_DIR", policy_dir):
                yield target
        finally:
            policy.clear_policy_cache()


def invalid_records(fact):
    """Single-field mutations of known valid consumer inputs."""
    fields = ("id", "kind", "schema") + REQUIRED[fact["kind"]]
    for field in fields:
        bad = copy.deepcopy(fact)
        del bad[field]
        yield f"missing {field}", bad
    optional = ("meaning",)
    if fact["kind"] == "enum-includes":
        optional += ("definition",)
    if fact["kind"] == "param-property-enum":
        optional += ("method",)
    for field in fields + optional:
        replacements = BAD_STRING
        if field in ARRAY_FIELDS:
            replacements = (None, False, 0, "private/fact-value", {}, [False], [0], [{}])
        elif field == "objects":
            replacements = (None, False, 0, "private/fact-value", [])
        elif field in ("default", "definition") or (field == "method" and fact["kind"] == "param-property-enum"):
            replacements = (False, 0, [], {})
        for value in replacements:
            bad = copy.deepcopy(fact)
            bad[field] = value
            yield f"invalid {field}", bad
    for value in ("unknown-offline-fact", [], {}):
        yield "unsupported kind", {**fact, "kind": value}
    yield "unknown field", {**fact, "private/fact-value": {"secret": True}}
    yield "non-string key", {**fact, 1: "private/fact-value"}


def union_case(shape):
    """Valid fake protocol schemas, independent of executable or captured source."""
    fact = {
        "id": "synthetic-union", "kind": "response-decision-union", "schema": "stable/ServerRequest.json",
        "bundle": "stable", "method": "synthetic/requestApproval", "decision_field": "decision",
        "strings": ["accept"], "objects": {"amend": shape},
    }
    server = {"oneOf": [{
        "type": "object",
        "properties": {"method": {"enum": ["synthetic/requestApproval"]},
                       "params": {"$ref": "#/definitions/SyntheticParams"}},
        "required": ["method", "params"],
    }]}
    server["definitions"] = {"SyntheticParams": {"type": "object", "properties": {}, "additionalProperties": False}}
    response = {
        "type": "object", "required": ["decision"],
        "properties": {"decision": {"$ref": "#/definitions/Decision"}},
        "definitions": {"Decision": {"oneOf": [
            {"type": "string", "enum": ["accept"]},
            {"type": "object", "additionalProperties": False,
             "properties": {"amend": shape}, "required": ["amend"]},
        ]}},
    }
    return fact, {"stable/ServerRequest.json": server, "stable/SyntheticResponse.json": response}


@contextmanager
def synthetic_union(shape):
    fact, schemas = union_case(copy.deepcopy(shape))
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "stable").mkdir()
        for relative, schema in schemas.items():
            (root / relative).write_text(json.dumps(schema), encoding="utf-8")
        manifest = {"stable": pins.bundle_manifest(root / "stable")}
        yield fact, root, manifest


class FactMetadataTests(unittest.TestCase):
    def tearDown(self):
        policy.clear_policy_cache()

    def positive(self):
        loaded = pins.load_pins()
        self.assertEqual({pin["version"]: pin["status"] for pin in loaded},
                         {"0.163.0": "current", "0.162.0": "historical"})
        self.assertEqual(sum(len(pin["facts"]) for pin in loaded), 64)
        for pin in loaded:
            root = ROOT / "tests/fixtures/codex-protocol" / pin["version"]
            manifest = pins.load_manifest(pin, ROOT)
            self.assertEqual(pins.check_facts(pin, root, manifest), [])
            for fact in pin["facts"]:
                self.assertIsNone(pins.evaluate_fact(fact, root, manifest))
        return loaded

    def refused_before_io(self, fact):
        with patch.object(pins, "_schema", side_effect=AssertionError("invalid metadata reached I/O")) as reader:
            with self.assertRaises(pins.PinError) as raised:
                pins.evaluate_fact(fact, Path("unused"), {})
            self.assertTrue(str(raised.exception).startswith("codex-protocol-pins: "))
            self.assertNotIn("private/fact-value", str(raised.exception))
            with self.assertRaises(pins.PinError):
                pins.check_facts({"facts": [fact]}, Path("unused"), {})
            reader.assert_not_called()

    def supported_fact(self, fact, root, manifest):
        """Synthetic scratch facts exercise readers without creating pin evidence."""
        self.assertIsNone(pins.evaluate_fact(fact, root, manifest))
        with copied_policy() as path:
            self.positive()
            document = json.loads(path.read_text(encoding="utf-8"))
            document["pins"][0]["facts"] = [fact]
            path.write_text(json.dumps(document), encoding="utf-8")
            policy.clear_policy_cache()
            loaded = pins.load_pins()
            self.assertEqual(pins.check_facts(loaded[0], root, manifest), [])

    def test_every_kind_rejects_missing_wrong_and_unexpected_fields_at_both_boundaries(self):
        self.assertEqual(set(REQUIRED), set(pins.FACT_KINDS))
        for pin_index in range(2):
            with copied_policy() as path:
                original = json.loads(path.read_text(encoding="utf-8"))
                samples = {}
                for index, fact in enumerate(original["pins"][pin_index]["facts"]):
                    samples.setdefault(fact["kind"], (index, fact))
                self.assertEqual(set(samples), set(REQUIRED))
                for kind, (index, fact) in samples.items():
                    for label, bad in invalid_records(fact):
                        with self.subTest(pin=pin_index, kind=kind, case=label):
                            path.write_text(json.dumps(original), encoding="utf-8")
                            policy.clear_policy_cache()
                            self.positive()
                            changed = copy.deepcopy(original)
                            changed["pins"][pin_index]["facts"][index] = bad
                            path.write_text(json.dumps(changed), encoding="utf-8")
                            policy.clear_policy_cache()
                            with self.assertRaises(pins.PinError):
                                pins.load_pins()
                            self.refused_before_io(bad)

    def test_direct_tuple_arrays_refuse_but_json_roundtrips_to_valid_arrays(self):
        # A Python tuple is invalid direct metadata, but JSON encodes it as an
        # ordinary array. Do not demand that the file reader reject that array.
        for pin_index in range(2):
            with copied_policy() as path:
                original = json.loads(path.read_text(encoding="utf-8"))
                samples = {}
                for index, fact in enumerate(original["pins"][pin_index]["facts"]):
                    samples.setdefault(fact["kind"], (index, fact))
                for kind, (index, fact) in samples.items():
                    for field in sorted(ARRAY_FIELDS.intersection(fact)):
                        with self.subTest(pin=pin_index, kind=kind, field=field):
                            path.write_text(json.dumps(original), encoding="utf-8")
                            policy.clear_policy_cache()
                            self.positive()
                            direct = copy.deepcopy(fact)
                            direct[field] = tuple(direct[field])
                            self.refused_before_io(direct)
                            encoded = json.loads(json.dumps(direct))
                            self.assertIs(type(encoded[field]), list)
                            self.assertEqual(encoded, fact)
                            document = copy.deepcopy(original)
                            document["pins"][pin_index]["facts"][index] = encoded
                            path.write_text(json.dumps(document), encoding="utf-8")
                            policy.clear_policy_cache()
                            self.positive()

    def test_mapping_keys_cannot_replace_a_values_array(self):
        loaded = self.positive()
        for pin in loaded:
            fact = copy.deepcopy(next(f for f in pin["facts"] if f["kind"] == "methods-equal"))
            fact["values"] = dict.fromkeys(fact["values"], True)
            self.refused_before_io(fact)
            with copied_policy() as path:
                document = json.loads(path.read_text(encoding="utf-8"))
                self.positive()
                target = next(p for p in document["pins"] if p["version"] == pin["version"])
                target["facts"][0] = fact
                path.write_text(json.dumps(document), encoding="utf-8")
                policy.clear_policy_cache()
                with self.assertRaises(pins.PinError):
                    pins.load_pins()

    def test_records_containers_duplicates_and_minimal_empty_wrapper(self):
        fact = self.positive()[0]["facts"][0]
        for bad in (None, False, 0, "private/fact-value", []):
            self.refused_before_io(bad)
        with patch.object(pins, "_schema", side_effect=AssertionError("wrapper reached I/O")) as reader:
            for wrapper in (None, [], {}, {"facts": None}, {"facts": {}}, {"facts": ""}, {"facts": ()},
                            {"facts": [fact, fact]}):
                with self.subTest(wrapper=type(wrapper).__name__), self.assertRaises(pins.PinError):
                    pins.check_facts(wrapper, Path("unused"), {})
            self.assertEqual(pins.check_facts(MappingProxyType({"facts": []}), Path("unused"), {}), [])
            reader.assert_not_called()
        for facts in (None, {}, "", 0, True, [], [fact, fact]):
            with copied_policy() as path:
                document = json.loads(path.read_text(encoding="utf-8"))
                self.positive()
                document["pins"][0]["facts"] = facts
                path.write_text(json.dumps(document), encoding="utf-8")
                policy.clear_policy_cache()
                with self.assertRaises(pins.PinError):
                    pins.load_pins()

    def test_readonly_fact_and_unknown_version_refusal(self):
        pin = self.positive()[0]
        root = ROOT / "tests/fixtures/codex-protocol" / pin["version"]
        manifest = pins.load_manifest(pin, ROOT)
        self.assertIsNone(pins.evaluate_fact(MappingProxyType(pin["facts"][0]), root, manifest))
        with self.assertRaises(pins.PinError):
            pins.pin_for("0.164.0")

    def test_optional_null_empty_and_absent_selectors_and_explicit_default_none(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            schema = {"type": "object", "properties": {"choice": {"type": "string", "enum": ["a"]}}}
            (root / "Data.json").write_text(json.dumps(schema), encoding="utf-8")
            fact = {"id": "synthetic-inline", "kind": "param-property-enum", "schema": "Data.json",
                    "property": "choice", "definition": None, "values": ["a"], "default": None}
            for method in ("absent", None, ""):
                current = dict(fact)
                if method != "absent":
                    current["method"] = method
                self.supported_fact(current, root, {})
            enum = {"id": "synthetic-whole", "kind": "enum-includes", "schema": "Data.json", "values": ["a"]}
            for definition in ("absent", None, ""):
                current = dict(enum)
                if definition != "absent":
                    current["definition"] = definition
                self.supported_fact(current, root, {})
            missing = dict(fact)
            del missing["default"]
            self.refused_before_io(missing)
            (root / "Data.json").write_text("{}", encoding="utf-8")
            for kind, field in (("methods-equal", "values"), ("methods-include", "values"),
                                ("properties-absent", "names"), ("properties-present", "names"),
                                ("required-includes", "names"), ("enum-includes", "values")):
                empty = {"id": "synthetic-empty", "kind": kind, "schema": "Data.json", field: []}
                self.supported_fact(empty, root, {})
            (root / "Data.json").unlink()
            self.assertIn("schema unreadable", pins.evaluate_fact(empty, root, {}))

    def test_all_array_fields_accept_empty_metadata_without_new_minimums(self):
        pin = self.positive()[0]
        root = ROOT / "tests/fixtures/codex-protocol" / pin["version"]
        manifest = pins.load_manifest(pin, ROOT)
        for fact in pin["facts"]:
            for field in ARRAY_FIELDS.intersection(fact):
                empty = copy.deepcopy(fact)
                empty[field] = []
                problem = pins.evaluate_fact(empty, root, manifest)
                self.assertTrue(problem is None or isinstance(problem, str))


class ExpectedJsonDataTests(unittest.TestCase):
    refused_before_io = FactMetadataTests.refused_before_io
    positive = FactMetadataTests.positive

    def test_synthetic_false_to_zero_shape_change_is_a_mismatch(self):
        shape = {"type": "object", "properties": {}, "additionalProperties": False}
        with synthetic_union(shape) as (fact, root, manifest):
            self.assertIsNone(pins.evaluate_fact(fact, root, manifest))
            fact["objects"]["amend"]["additionalProperties"] = 0
            self.assertIsNotNone(pins.evaluate_fact(fact, root, manifest))
            with copied_policy() as path:
                self.positive()
                document = json.loads(path.read_text(encoding="utf-8"))
                document["pins"][0]["facts"] = [fact]
                path.write_text(json.dumps(document), encoding="utf-8")
                policy.clear_policy_cache()
                loaded = pins.load_pins()
                self.assertEqual(len(pins.check_facts(loaded[0], root, manifest)), 1)

    def test_empty_expected_collections_are_valid_metadata(self):
        shape = {"type": "object", "properties": {}}
        with synthetic_union(shape) as (fact, root, manifest):
            self.assertIsNone(pins.evaluate_fact(fact, root, manifest))
            for field, value in (("objects", {}), ("strings", [])):
                changed = copy.deepcopy(fact)
                changed[field] = value
                self.assertIsNotNone(pins.evaluate_fact(changed, root, manifest))

    def test_nested_types_and_list_order_differ_while_mapping_order_does_not(self):
        cases = (
            (False, 0, False), (True, 1, False), (0, False, False), (1, True, False),
            ([False], [0], False), ({"nested": [True]}, {"nested": [1]}, False),
            ([1, 2], [2, 1], False), ({"a": 1, "b": 2}, {"b": 2, "a": 1}, True),
            (1, 1.0, True),
        )
        for actual, expected, holds in cases:
            with self.subTest(actual=actual, expected=expected):
                shape = {"type": "object", "properties": {}, "additionalProperties": False, "default": actual}
                with synthetic_union(shape) as (fact, root, manifest):
                    self.assertIsNone(pins.evaluate_fact(fact, root, manifest))
                    fact["objects"]["amend"]["default"] = expected
                    problem = pins.evaluate_fact(fact, root, manifest)
                    self.assertEqual(problem is None, holds)

    def test_non_json_cycles_and_nonfinite_metadata_refuse_before_io(self):
        cycle_list = []
        cycle_list.append(cycle_list)
        cycle_dict = {}
        cycle_dict["cycle"] = cycle_dict
        bad_values = ((), set(), b"bytes", object(), {1: "private/fact-value"},
                      float("nan"), float("inf"), float("-inf"), cycle_list, cycle_dict)
        for value in bad_values:
            fact, _ = union_case({"type": "object", "default": value})
            self.refused_before_io(fact)

    def test_shared_acyclic_metadata_is_valid(self):
        shared = {"enabled": True}
        shape = {"type": "object", "properties": {}, "default": [shared, shared]}
        with synthetic_union(shape) as (fact, root, manifest):
            self.assertIsNone(pins.evaluate_fact(fact, root, manifest))

    def test_deep_and_wide_finite_data_has_no_metadata_recursion_or_size_budget(self):
        def shape():
            value = {"wide": list(range(10000)), "finite": 1.7976931348623157e308}
            for _ in range(2000):
                value = [value]
            return {"type": "object", "default": value}

        fact, schemas = union_case(shape())
        # In-memory fake protocol data isolates metadata/comparison from json.loads' own stack limit.
        schemas["stable/SyntheticResponse.json"]["definitions"]["Decision"]["oneOf"][1]["properties"]["amend"] = shape()
        with patch.object(pins, "_schema", side_effect=lambda root, relative: schemas[relative]):
            self.assertIsNone(pins.evaluate_fact(fact, Path("unused"), {"stable": {"SyntheticResponse.json": ""}}))


if __name__ == "__main__":
    unittest.main()
