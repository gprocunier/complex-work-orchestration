"""Unit component for the unregistered zero-trust consensus policy schema.

Registration below is TEST ONLY, to exercise validate_policy_document.
The production mapping and recorded partial boundary are unchanged.
"""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from typing import Any, Iterator
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import policy_schema as ps  # noqa: E402
from cwo_core.synthesis import zero_trust_route_requirement  # noqa: E402
from cwo_core.synthesis_inputs import consensus_policy_view  # noqa: E402

FILENAME = "zero-trust-consensus-policy.yaml"
SCHEMA_NAME = "zero-trust-consensus-policy.schema.json"
_DELETE = object()


def _walk(value: Any, path: tuple[Any, ...] = ()) -> Iterator[tuple[tuple[Any, ...], Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _walk(item, path + (key,))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk(item, path + (index,))


def _label(path: tuple[Any, ...]) -> str:
    result = "$"
    for step in path:
        result += f"[{step}]" if isinstance(step, int) else f".{step}"
    return result


class ZeroTrustConsensusPolicySchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        with (ROOT / "policy" / FILENAME).open(encoding="utf-8") as stream:
            self.document = json.load(stream)
        self.schema = ps.load_policy_schema(SCHEMA_NAME)
        self.assertEqual(ps.schema_errors(self.schema), [])
        # TEST ONLY: restore the actual mapping automatically after each test.
        self.enterContext(mock.patch.dict(ps.POLICY_SCHEMAS, {FILENAME: SCHEMA_NAME}))
        # Every negative starts with a positive using the real shipped document.
        self.validate(self.document)

    def validate(self, document: Any) -> None:
        ps.validate_policy_document(FILENAME, document)

    def changed(self, path: tuple[Any, ...], replacement: Any) -> Any:
        if not path:
            return copy.deepcopy(replacement)
        document = copy.deepcopy(self.document)
        parent = document
        for step in path[:-1]:
            parent = parent[step]
        if replacement is _DELETE:
            del parent[path[-1]]
        else:
            parent[path[-1]] = copy.deepcopy(replacement)
        return document

    def assert_rejected(self, document: Any, path: tuple[Any, ...] = ()) -> str:
        with self.assertRaises(ps.PolicySchemaError) as raised:
            self.validate(document)
        message = str(raised.exception)
        self.assertIn(FILENAME, message)
        self.assertIn(SCHEMA_NAME, message)
        self.assertIn(_label(path), message)
        return message

    def test_current_policy_reaches_existing_consumers(self) -> None:
        config = consensus_policy_view(self.document)
        self.assertEqual(config.version, self.document["version"])
        self.assertEqual(config.alias("codex"), "openai")
        result = zero_trust_route_requirement(
            "Use zero-trust consensus to review TLS implementation.", policy=self.document,
        )
        self.assertTrue(result["zero_trust_consensus_required"])
        self.assertEqual(result["zero_trust_minimum_independent_domains"], self.document["defaults"]["minimum_independent_domains"])

    def test_every_shipped_value_has_a_structural_type_check(self) -> None:
        for path, value in _walk(self.document):
            if isinstance(value, dict):
                replacement = []
            elif isinstance(value, list):
                replacement = {}
            elif type(value) is int:
                replacement = True
            else:
                self.assertIsInstance(value, str)
                replacement = 7
            with self.subTest(path=_label(path)):
                self.assert_rejected(self.changed(path, replacement), path)

    def test_integer_tokens_refuse_floats_strings_null_and_booleans(self) -> None:
        for path, value in _walk(self.document):
            if type(value) is not int:
                continue
            for replacement in (float(value), str(value), None, False):
                with self.subTest(path=_label(path), replacement=replacement):
                    self.assert_rejected(self.changed(path, replacement), path)

    def test_required_fields_cannot_disappear(self) -> None:
        paths = [(name,) for name in ("version", "defaults", "status_values", "resolution_authority")]
        paths.append(("defaults", "minimum_independent_domains"))
        paths.extend(("claim_categories", name, "weight") for name in self.document["claim_categories"])
        for path in paths:
            with self.subTest(path=_label(path)):
                message = self.assert_rejected(self.changed(path, _DELETE), path[:-1])
                self.assertIn(f"missing required field {path[-1]!r}", message)

    def test_closed_records_refuse_unknown_fields(self) -> None:
        dynamic_maps = {("claim_categories",), ("trust_domain_resolution", "domain_aliases")}
        for path, value in _walk(self.document):
            if not isinstance(value, dict) or path in dynamic_maps:
                continue
            with self.subTest(path=_label(path)):
                self.assert_rejected(self.changed(path + ("zz_unexpected",), True), path + ("zz_unexpected",))

    def test_array_items_are_checked(self) -> None:
        for path, value in _walk(self.document):
            if not isinstance(value, list) or not value:
                continue
            with self.subTest(path=_label(path)):
                self.assert_rejected(self.changed(path + (0,), None), path + (0,))

    def test_declared_contract_values(self) -> None:
        cases = (
            (("version",), 2),
            (("defaults", "minimum_independent_domains"), 1),
            (("status_values", 0), "validated"),
            (("recommended_actions", 0), "approve"),
            (("routing_triggers", "required_risk_levels", 0), "extreme"),
            (("resolution_authority",), "worker"),
        )
        for path, replacement in cases:
            with self.subTest(path=_label(path), replacement=replacement):
                self.assert_rejected(self.changed(path, replacement), path)

    def test_weights_and_thresholds_are_not_pinned_to_current_values(self) -> None:
        paths = [("thresholds", name) for name in self.document["thresholds"]]
        paths.extend(("claim_categories", name, "weight") for name in self.document["claim_categories"])
        for path in paths:
            for replacement in (-3, 0, 100001):
                with self.subTest(path=_label(path), replacement=replacement):
                    self.validate(self.changed(path, replacement))
        self.validate(self.changed(("defaults", "minimum_independent_domains"), 3))
        self.validate(self.changed(("weakness_pattern_source_version",), 2))

    def test_dynamic_maps_and_scalar_category_weights(self) -> None:
        for categories in ({}, {"fresh-category": {"weight": 17}}, {"fresh-category": -3}):
            with self.subTest(categories=categories):
                document = self.changed(("claim_categories",), categories)
                self.validate(document)
                expected = {key: value["weight"] if isinstance(value, dict) else value for key, value in categories.items()}
                self.assertEqual(dict(consensus_policy_view(document).category_weights), expected)
        aliases = self.changed(("trust_domain_resolution", "domain_aliases"), {"New Alias": "New Family"})
        self.validate(aliases)
        self.assertEqual(consensus_policy_view(aliases).alias("new alias"), "new family")
        for value in (False, 1.0, "1", None, {}, []):
            with self.subTest(category_value=value):
                self.assert_rejected(self.changed(("claim_categories", "fresh-category"), value), ("claim_categories", "fresh-category"))
        for value in (False, 1, None, {}, []):
            with self.subTest(alias_value=value):
                self.assert_rejected(self.changed(("trust_domain_resolution", "domain_aliases", "fresh"), value), ("trust_domain_resolution", "domain_aliases", "fresh"))

    def test_optional_fields_preserve_consumer_fallbacks(self) -> None:
        required = {"version", "defaults", "status_values", "resolution_authority"}
        for name in sorted(self.document.keys() - required):
            with self.subTest(root_field=name):
                document = self.changed((name,), _DELETE)
                self.validate(document)
                consensus_policy_view(document)
        for section in ("thresholds", "routing_triggers", "trust_domain_resolution"):
            for name in self.document[section]:
                with self.subTest(section=section, field=name):
                    document = self.changed((section, name), _DELETE)
                    self.validate(document)
                    consensus_policy_view(document)
        for name in self.document["weakness_patterns"][0]:
            with self.subTest(pattern_field=name):
                document = self.changed(("weakness_patterns", 0, name), _DELETE)
                self.validate(document)
                consensus_policy_view(document)

    def test_empty_and_duplicate_arrays_remain_valid(self) -> None:
        for path, value in _walk(self.document):
            if not isinstance(value, list):
                continue
            for replacement in ([], value + value):
                with self.subTest(path=_label(path), replacement=replacement):
                    document = self.changed(path, replacement)
                    self.validate(document)
                    consensus_policy_view(document)

    def test_legacy_field_precedence_fallback(self) -> None:
        resolution = copy.deepcopy(self.document["trust_domain_resolution"])
        del resolution["claimed_domain_fields"]
        resolution["field_precedence"] = ["deployment_family", "deployment_family"]
        document = self.changed(("trust_domain_resolution",), resolution)
        self.validate(document)
        self.assertEqual(consensus_policy_view(document).claimed_domain_fields, ("deployment_family", "deployment_family"))
        resolution["claimed_domain_fields"] = []
        document = self.changed(("trust_domain_resolution",), resolution)
        self.validate(document)
        self.assertEqual(consensus_policy_view(document).claimed_domain_fields, ("deployment_family", "deployment_family"))
        del resolution["field_precedence"]
        document = self.changed(("trust_domain_resolution",), resolution)
        self.validate(document)
        self.assertEqual(
            consensus_policy_view(document).claimed_domain_fields,
            ("trust_domain", "provider_family", "provider_camp"),
        )
        for replacement in ("trust_domain", [1], None):
            with self.subTest(field_precedence=replacement):
                self.assert_rejected(self.changed(("trust_domain_resolution", "field_precedence"), replacement), ("trust_domain_resolution", "field_precedence"))

    def test_permissive_metadata_and_pattern_shapes(self) -> None:
        for path in (
            ("schema",), ("scope",), ("trust_domain_independence_disclaimer",),
            ("trust_domain_resolution", "domain_source"), ("trust_domain_resolution", "unknown_domain"),
        ):
            with self.subTest(path=_label(path)):
                self.validate(self.changed(path, ""))
        for pattern in ({}, {"terms": []}, {"id": "new-id", "category": "new-category", "severity": "custom", "terms": ["", "x", "x"]}):
            with self.subTest(pattern=pattern):
                document = self.changed(("weakness_patterns",), [pattern])
                self.validate(document)
                consensus_policy_view(document)


if __name__ == "__main__":
    unittest.main()
