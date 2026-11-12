"""Unregistered acceptance schema component; loader registration below is TEST ONLY."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import policy, policy_schema as ps, return_sections, returns  # noqa: E402

FILENAME = "acceptance-policy.yaml"
SCHEMA_NAME = "acceptance-policy.schema.json"


def nodes(
    schema: dict[str, Any], value: Any, path: tuple[Any, ...] = (),
) -> Iterator[tuple[tuple[Any, ...], dict[str, Any], Any]]:
    """Visit actual document nodes with their declared component schemas."""
    yield path, schema, value
    if type(value) is dict:
        for key, item in value.items():
            child = schema.get("properties", {}).get(key, schema.get("additionalProperties"))
            if type(child) is dict:
                yield from nodes(child, item, path + (key,))
    elif type(value) is list:
        for index, item in enumerate(value):
            yield from nodes(schema["items"], item, path + (index,))


def replace(document: Any, path: tuple[Any, ...], value: Any) -> Any:
    result = copy.deepcopy(document)
    if not path:
        return copy.deepcopy(value)
    parent = result
    for step in path[:-1]:
        parent = parent[step]
    parent[path[-1]] = copy.deepcopy(value)
    return result


class AcceptancePolicySchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = ps.load_policy_schema(SCHEMA_NAME)
        with (ROOT / "policy" / FILENAME).open(encoding="utf-8") as stream:
            self.document = json.load(stream)
        self.assertEqual(ps.schema_errors(self.schema), [])
        self.assertEqual(ps.validate_instance(self.document, self.schema), [])
        # TEST ONLY: exercise the real validator without production registration.
        # This fixture is not evidence that canonical production loads are covered.
        registration = mock.patch.dict(ps.POLICY_SCHEMAS, {FILENAME: SCHEMA_NAME})
        registration.start()
        self.addCleanup(registration.stop)
        ps.validate_policy_document(FILENAME, self.document)

    def assert_refused(self, document: Any, *fragments: str) -> None:
        with self.assertRaises(ps.PolicySchemaError) as raised:
            ps.validate_policy_document(FILENAME, document)
        for fragment in fragments:
            self.assertIn(fragment, str(raised.exception))

    @contextmanager
    def loaded_document(self, document: dict[str, Any]) -> Iterator[None]:
        """Real canonical loader, disposable input and TEST ONLY registration."""
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / FILENAME).write_text(json.dumps(document), encoding="utf-8")
            policy.clear_policy_cache()
            return_sections.return_section_aliases.cache_clear()
            try:
                with mock.patch.object(policy, "POLICY_DIR", directory):
                    yield
            finally:
                policy.clear_policy_cache()
                return_sections.return_section_aliases.cache_clear()

    def test_current_document_and_supported_closed_root(self) -> None:
        self.assertIs(self.schema["additionalProperties"], False)
        with self.loaded_document(self.document):
            self.assertEqual(policy.load_policy("acceptance-policy"), self.document)
            self.assertEqual(policy.load_policy(FILENAME), self.document)
            self.assertEqual(returns.evidence_quality_thresholds(), self.document["evidence_quality"]["thresholds"])
            self.assertEqual(
                return_sections.canonical_return_section("recommended next action"),
                "Recommended next bead",
            )

    def test_wrong_type_at_every_current_node(self) -> None:
        replacements = {
            "object": [], "array": {}, "string": 7,
            "integer": True, "number": True, "boolean": "false",
        }
        for path, schema, value in nodes(self.schema, self.document):
            with self.subTest(path=path):
                self.assert_refused(replace(self.document, path, replacements[schema["type"]]), "expected")

    def test_closed_records_and_required_fields(self) -> None:
        for path, schema, value in nodes(self.schema, self.document):
            if schema["type"] != "object":
                continue
            if schema["additionalProperties"] is False:
                changed = copy.deepcopy(value)
                changed["zz_unexpected"] = None
                with self.subTest(path=path, case="extra"):
                    self.assert_refused(replace(self.document, path, changed), "zz_unexpected: unexpected field")
            for key in schema.get("required", []):
                changed = copy.deepcopy(value)
                del changed[key]
                with self.subTest(path=path, missing=key):
                    self.assert_refused(replace(self.document, path, changed), f"missing required field {key!r}")

    def test_wrong_array_items(self) -> None:
        for path, schema, value in nodes(self.schema, self.document):
            if schema["type"] == "array":
                with self.subTest(path=path):
                    self.assert_refused(replace(self.document, path, [*value, None]), f"[{len(value)}]", "expected string")

    def test_exact_version_integer(self) -> None:
        for value in (True, False, 2.0, "2", None, 1, 3):
            with self.subTest(value=value):
                self.assert_refused(replace(self.document, ("version",), value), "$.version")

    def test_numbers_exclude_booleans_strings_and_null(self) -> None:
        for path, schema, value in nodes(self.schema, self.document):
            if schema["type"] != "number":
                continue
            for bad in (False, True, str(value), None):
                with self.subTest(path=path, bad=bad):
                    self.assert_refused(replace(self.document, path, bad), "expected number")
            # No new threshold constants, integer-only restriction or bounds.
            for number in (0, 0.5, value + 1):
                with self.subTest(path=path, number=number):
                    ps.validate_policy_document(FILENAME, replace(self.document, path, number))

    def test_optional_fields_empty_arrays_and_duplicates(self) -> None:
        for path, schema, value in nodes(self.schema, self.document):
            if schema["type"] == "object":
                for key in value:
                    if key in schema.get("required", []):
                        continue
                    changed = copy.deepcopy(value)
                    del changed[key]
                    with self.subTest(path=path, omitted=key):
                        ps.validate_policy_document(FILENAME, replace(self.document, path, changed))
            elif schema["type"] == "array":
                for items in ([], [*value, *value]):
                    with self.subTest(path=path, items=items):
                        ps.validate_policy_document(FILENAME, replace(self.document, path, items))

    def test_dynamic_aliases_and_signal_notes(self) -> None:
        document = copy.deepcopy(self.document)
        document["contractor_return_required_sections"].append("Local diagnostic")
        document["return_section_aliases"]["local diagnostic alias"] = "Local diagnostic"
        document["sabotage"]["signal_notes"]["local_diagnostic"] = {
            "authority": "diagnostic metadata", "intent_finding": "not asserted", "meaning": "data",
        }
        ps.validate_policy_document(FILENAME, document)
        with self.loaded_document(document):
            self.assertEqual(return_sections.canonical_return_section("local diagnostic alias"), "Local diagnostic")
        for path in (
            ("return_section_aliases", "local diagnostic alias"),
            ("sabotage", "signal_notes", "local_diagnostic", "meaning"),
        ):
            with self.subTest(path=path):
                self.assert_refused(replace(document, path, False), "expected string")

    def test_legacy_aliases_and_evidence_fallbacks_are_unchanged(self) -> None:
        document = copy.deepcopy(self.document)
        document["return_section_alias_source"] = " LEGACY "
        del document["return_section_aliases"]
        ps.validate_policy_document(FILENAME, document)
        with self.loaded_document(document):
            self.assertEqual(
                return_sections.canonical_return_section("recommended next action"),
                return_sections.RETURN_SECTION_ALIASES["recommended next action"],
            )
        for key, fallback in {"primary": 85, "salvage": 60, "reject_below": 40}.items():
            document = copy.deepcopy(self.document)
            del document["evidence_quality"]["thresholds"][key]
            ps.validate_policy_document(FILENAME, document)
            with self.loaded_document(document):
                self.assertEqual(returns.evidence_quality_thresholds()[key], fallback)

    def test_test_only_registration_refuses_before_shown_consumers(self) -> None:
        cases = (
            (("evidence_quality", "thresholds", "primary"), returns.evidence_quality_thresholds),
            (("return_section_aliases", "peer review disposition"), return_sections.return_section_aliases),
            (("score", "start"), lambda: policy.load_policy("acceptance-policy.yaml")),
        )
        for path, call in cases:
            with self.subTest(path=path):
                with self.loaded_document(replace(self.document, path, False)):
                    with self.assertRaises(ps.PolicySchemaError) as raised:
                        call()
                self.assertIn(f"policy/{FILENAME} does not match", str(raised.exception))
                self.assertIn(".".join(map(str, path)), str(raised.exception))

    def test_strict_parser_still_refuses_duplicate_keys(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate key 'version'"):
            ps.strict_json_loads('{"version": 2, "version": 2}')


if __name__ == "__main__":
    unittest.main()
