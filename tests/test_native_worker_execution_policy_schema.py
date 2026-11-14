"""Registered shape component; disposable mapping overrides remain TEST ONLY."""

from __future__ import annotations

import copy
import json
import sys
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import policy, policy_schema as ps  # noqa: E402
import shutil
import tempfile

FILENAME = "native-worker-execution.yaml"
SCHEMA_NAME = "native-worker-execution-policy.schema.json"
_DELETE = object()


@contextmanager
def _test_only_registration():
    """TEST ONLY: restore the mapping and both caches even after refusal."""
    policy.clear_policy_cache()
    ps.clear_schema_cache()
    try:
        with mock.patch.dict(ps.POLICY_SCHEMAS, {FILENAME: SCHEMA_NAME}):
            yield
    finally:
        policy.clear_policy_cache()
        ps.clear_schema_cache()


def _replace(document, path, replacement):
    # Matrix rows share only immutable fixture bytes; every validator gets its
    # own complete mutable document. Other callers retain deepcopy semantics.
    result = json.loads(document) if isinstance(document, str) else copy.deepcopy(document)
    if not path:
        return copy.deepcopy(replacement)
    parent = result
    for step in path[:-1]:
        parent = parent[step]
    if replacement is _DELETE:
        del parent[path[-1]]
    else:
        parent[path[-1]] = copy.deepcopy(replacement)
    return result


def _locations(value, schema, path=()):
    yield path, value, schema
    if type(value) is dict:
        for key, item in value.items():
            child = schema.get("properties", {}).get(key)
            if child is None:
                child = schema["additionalProperties"]
            if type(child) is not dict:
                raise AssertionError(f"actual policy field lacks a value schema: {path + (key,)}")
            yield from _locations(item, child, path + (key,))
    elif type(value) is list:
        for index, item in enumerate(value):
            yield from _locations(item, schema["items"], path + (index,))


def _types(node):
    declared = node["type"]
    return {declared} if isinstance(declared, str) else set(declared)


def _type_cases(node):
    types = _types(node)
    primary = next(name for name in types if name != "null")
    wrong = {
        "object": (("array", []), ("string", "object"), ("boolean", True), ("integer", 7)),
        "array": (("object", {}), ("string", "array"), ("boolean", True), ("integer", 7)),
        "string": (("integer", 7), ("boolean", False), ("array", []), ("object", {})),
        "integer": (("true", True), ("false", False), ("integral float", 1.0), ("fraction", 1.5), ("numeric string", "1"), ("array", []), ("object", {})),
        "number": (("true", True), ("false", False), ("numeric string", "0.5"), ("array", []), ("object", {})),
        "boolean": (("zero", 0), ("one", 1), ("string", "false"), ("array", []), ("object", {})),
    }
    for label, replacement in wrong[primary]:
        integral = primary == "integer" and type(replacement) is float and replacement.is_integer()
        yield label, replacement, False, integral
    if "null" not in types:
        yield "null", None, False, False

def _object_cases(value, node):
    extra = node["additionalProperties"]
    if extra is False:
        changed = copy.deepcopy(value)
        changed["zz_unexpected"] = 0
        yield "unknown field", changed, False, False
    elif value:
        changed = copy.deepcopy(value)
        changed["alternative-identifier"] = copy.deepcopy(next(iter(value.values())))
        yield "dynamic identifier", changed, True, False
    if not node.get("required"):
        yield "empty object", {}, True, False
    for name in value:
        changed = copy.deepcopy(value)
        del changed[name]
        yield f"omitted {name}", changed, name not in node.get("required", []), False

def _array_cases(value, node):
    yield "empty array", [], True, False
    if value:
        yield "duplicate item", [copy.deepcopy(value[0]), copy.deepcopy(value[0])], True, False
    for label, replacement, expected, integral in _type_cases(node["items"]):
        yield f"item {label}", [replacement], expected, integral

def _scalar_cases(node):
    if "const" in node:
        yield "changed constant", 0, False, False
        yield "changed constant", 2, False, False
        return
    types = _types(node)
    primary = next(name for name in types if name != "null")
    controls = {
        "string": ("", "different declared metadata"),
        "integer": (-7, 0, 123456),
        "number": (-0.5, 0, 2.5),
        "boolean": (True, False),
    }
    for replacement in controls[primary]:
        yield repr(replacement), replacement, True, False
    if "null" in types:
        yield "nullable", None, True, False

def _matrix(document, schema):
    yield "original", document, True, False
    for path, value, node in _locations(document, schema):
        label = "/".join(map(str, path)) or "$"
        for mutation, replacement, expected, integral in _type_cases(node):
            yield f"{label}: {mutation}", _replace(document, path, replacement), expected, integral
        if type(value) is dict:
            controls = _object_cases(value, node)
        elif type(value) is list:
            controls = _array_cases(value, node)
        else:
            controls = _scalar_cases(node)
        for mutation, replacement, expected, integral in controls:
            yield f"{label}: {mutation}", _replace(document, path, replacement), expected, integral


def _schema_nodes(node):
    yield node
    for child in node.get("properties", {}).values():
        yield from _schema_nodes(child)
    extra = node.get("additionalProperties")
    if type(extra) is dict:
        yield from _schema_nodes(extra)
    if "items" in node:
        yield from _schema_nodes(node["items"])


@contextmanager
def _test_only_policy(document=None):
    """TEST ONLY: copy the complete actual file before any fixture mutation."""
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / FILENAME
        shutil.copyfile(ROOT / "policy" / FILENAME, path)
        if document is not None:
            path.write_text(json.dumps(document), encoding="utf-8")
        with _test_only_registration(), mock.patch.object(policy, "POLICY_DIR", Path(directory)):
            yield


class NativeWorkerExecutionPolicySchemaTests(unittest.TestCase):
    def setUp(self):
        self.schema = ps.load_policy_schema(SCHEMA_NAME)
        self.document = ps.strict_json_loads((ROOT / "policy" / FILENAME).read_text(encoding="utf-8"))
        self.assertEqual(ps.schema_errors(self.schema), [])
        self.assertEqual(ps.validate_instance(self.document, self.schema), [])

    def _check_bounded(self, label, document, expected):
        self.assertEqual(not ps.validate_instance(document, self.schema), expected, label)
        if expected:
            ps.validate_policy_document(FILENAME, document)
        else:
            with self.assertRaises(ps.PolicySchemaError) as raised:
                ps.validate_policy_document(FILENAME, document)
            self.assertIn(f"policy/{FILENAME}", str(raised.exception))

    def test_schema_covers_complete_current_document_without_new_value_limits(self):
        self.assertEqual(len(self.document), 43)
        self.assertEqual(set(self.document), set(self.schema["properties"]))
        for path, value, node in _locations(self.document, self.schema):
            with self.subTest(path=path):
                self.assertIn("type", node)
                self.assertEqual(ps.validate_instance(value, node), [])
        for node in _schema_nodes(self.schema):
            self.assertFalse(set(node) & {"minimum", "maximum", "minItems", "uniqueItems", "enum", "minLength"})
            self.assertEqual(node.get("required", []), ["version"] if node is self.schema else [])
            if "object" in _types(node):
                self.assertIsNot(node["additionalProperties"], True)
        self.assertEqual(self.schema["properties"]["version"], {"type": "integer", "const": 1})

    def test_nullable_deadlines_and_dynamic_maps_are_shape_only(self):
        paths = [
            ("packet_v3", "phases"),
            ("lane_budgets",),
            ("work_sizing", "enforcement"),
            ("work_sizing", "enforcement", "foundation-canary", "task_class_policy"),
            ("work_sizing", "enforcement", "foundation-canary", "protected_surfaces"),
            ("work_sizing", "enforcement", "foundation-canary", "commitment", "normalization", "decision_aliases"),
            ("task_selected_routing", "operative_roles"),
        ]
        with _test_only_registration():
            for path in paths:
                value = self.document
                for step in path:
                    value = value[step]
                changed = _replace(self.document, path, {"alternative-identifier": copy.deepcopy(next(iter(value.values())))})
                self._check_bounded(str(path), changed, True)
            for deadline in (None, 0, 17):
                path = ("packet_v3", "phases", "implementation", "mutation_deadline_seconds")
                self._check_bounded(str(deadline), _replace(self.document, path, deadline), True)

    def test_component_is_registered_and_test_mapping_is_restored(self):
        self.assertEqual(len(ps.POLICY_SCHEMAS), 20)
        self.assertEqual(ps.POLICY_SCHEMAS[FILENAME], SCHEMA_NAME)
        self.assertEqual(
            ps.POLICY_SCHEMAS["qualification-target.yaml"], "qualification-target.schema.json"
        )
        self.assertEqual(ps.POLICY_VALIDATION_BOUNDARIES[FILENAME][0], "schema")
        before = dict(ps.POLICY_SCHEMAS)
        before_directory = policy.POLICY_DIR
        with _test_only_registration():
            self.assertEqual(ps.POLICY_SCHEMAS[FILENAME], SCHEMA_NAME)
            ps.validate_policy_document(FILENAME, self.document)
        with self.assertRaisesRegex(RuntimeError, "EXAMPLE exceptional fixture exit"):
            with _test_only_policy():
                self.assertEqual(policy.load_policy(FILENAME), self.document)
                self.assertGreater(policy._load_policy_cached.cache_info().currsize, 0)
                self.assertGreater(ps._load_schema_cached.cache_info().currsize, 0)
                raise RuntimeError("EXAMPLE exceptional fixture exit")
        self.assertEqual(ps.POLICY_SCHEMAS, before)
        self.assertIs(policy.POLICY_DIR, before_directory)
        self.assertEqual(policy._load_policy_cached.cache_info().currsize, 0)
        self.assertEqual(ps._load_schema_cached.cache_info().currsize, 0)
        self.assertTrue(ps.policy_document_errors(FILENAME, _replace(self.document, ("version",), True)))


    def test_canonical_loader_uses_disposable_copy_and_restores_mapping(self):
        before = (ROOT / "policy" / FILENAME).read_bytes()
        variants = [
            (("version",), True),
            (("version",), _DELETE),
            (("zz_unexpected",), True),
            (("precommit_containment", "active"), 1),
            (("native_release_evidence", "version"), True),
            (("precommit_supervision", "poll_interval_ms"), "1000"),
            (("native_supervision_pool", "scheduler"), []),
            (("packet_v3", "phases", "review", "mutation_deadline_seconds"), "30"),
            (("work_sizing", "enforcement", "foundation-canary", "task_class_policy", "diagnosis", "tool_calls_p90"), False),
            (("task_selected_routing", "operative_roles"), {"new-model": False}),
        ]
        for path, replacement in variants:
            changed = _replace(self.document, path, replacement)
            for spelling in ("native-worker-execution", FILENAME):
                with self.subTest(path=path, spelling=spelling):
                    with _test_only_policy():
                        self.assertEqual(policy.load_policy(spelling), self.document)
                    with _test_only_policy(changed):
                        with self.assertRaises(ps.PolicySchemaError) as raised:
                            policy.load_policy(spelling)
                        self.assertIn(f"policy/{FILENAME}", str(raised.exception))
        self.assertEqual((ROOT / "policy" / FILENAME).read_bytes(), before)
        self.assertEqual(ps.POLICY_SCHEMAS[FILENAME], SCHEMA_NAME)
        self.assertEqual(policy._load_policy_cached.cache_info().currsize, 0)


    def test_full_mutation_matrix_matches_independent_test_only_validator(self):
        try:
            import jsonschema
        except ImportError as exc:
            self.fail(f"test-only jsonschema dependency is required: {exc}")
        jsonschema.Draft202012Validator.check_schema(self.schema)
        reference = jsonschema.Draft202012Validator(self.schema)
        totals = {"cases": 0, "accepted": 0, "rejected": 0, "integer_token_divergences": 0}
        bounded_seconds = reference_seconds = 0.0
        with _test_only_registration():
            for label, document, expected, integral in _matrix(self.document, self.schema):
                with self.subTest(case=label):
                    started = time.perf_counter()
                    self._check_bounded(label, document, expected)
                    bounded_seconds += time.perf_counter() - started
                    started = time.perf_counter()
                    reference_ok = reference.is_valid(document)
                    reference_seconds += time.perf_counter() - started
                    self.assertEqual(reference_ok, expected or integral, label)
                    totals["cases"] += 1
                    totals["accepted" if expected else "rejected"] += 1
                    totals["integer_token_divergences"] += int(reference_ok and not expected)
            # The matrix starts with the original at all three entry points.
            # Repeat that control after the batch, rather than before every mutation.
            self._check_bounded("original after matrix", self.document, True)
            self.assertTrue(reference.is_valid(self.document))
        self.assertEqual(self.document, ps.strict_json_loads((ROOT / "policy" / FILENAME).read_text(encoding="utf-8")))
        self.assertGreater(totals["accepted"], 1)
        self.assertGreater(totals["rejected"], 0)
        print(json.dumps({
            "component": SCHEMA_NAME, "python": sys.version, **totals,
            "bounded_seconds": bounded_seconds, "reference_seconds": reference_seconds,
            "timing_scope": "generated complete documents including original first case; final original control and setup excluded",
        }, sort_keys=True), flush=True)


if __name__ == "__main__":
    unittest.main()
