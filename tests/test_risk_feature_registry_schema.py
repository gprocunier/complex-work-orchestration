"""Risk-feature configuration shape is checked at canonical load and real consumers."""

from __future__ import annotations

import json
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import policy, risk_features  # noqa: E402
from cwo_core.errors import CWOValidationError  # noqa: E402
from cwo_core.policy_schema import PolicySchemaError, load_policy_schema  # noqa: E402
from cwo_core.routing import classify_work  # noqa: E402
from tests.test_policy_schema import malformed_policy  # noqa: E402


def clear_caches() -> None:
    policy.clear_policy_cache()
    risk_features._policy.cache_clear()


@contextmanager
def copied_risk_policy(mutate: Callable[[dict[str, Any]], None] | None = None,
                       *, raw: str | None = None) -> Iterator[Path]:
    clear_caches()
    try:
        with malformed_policy("risk-features", mutate, raw) as directory:
            yield directory
    finally:
        clear_caches()


class RiskFeatureRegistrySchemaTests(unittest.TestCase):
    """Real positives precede copied malformed configurations in every test."""

    def setUp(self) -> None:
        clear_caches()
        self.addCleanup(clear_caches)
        self.document = json.loads((ROOT / "policy" / "risk-features.yaml").read_text(encoding="utf-8"))
        # Establish actual consumer success before any malformed configuration.
        self.assertEqual(policy.load_policy("risk-features"), self.document)
        assessment = risk_features.assess_risk_features("Inspect OIDC")
        self.assertEqual(assessment.features, {"asset:authentication": ["oidc"]})
        self.assertEqual(assessment.floor, "high")
        self.assertEqual(assessment.required_experts, ["security"])
        route = classify_work("Inspect OIDC")
        self.assertEqual(route["risk_assessment"]["floor"], "high")
        self.assertIn("security", {expert["name"] for expert in route["ranked_experts"]})
        self.assertFalse(route["operative_route"]["dispatch_authorized"])
        production = risk_features.assess_risk_features("Migrate production")
        self.assertEqual(set(production.features), {"action:migration", "environment:production"})
        self.assertEqual(production.floor, "high")
        self.assertEqual(production.required_experts, ["architecture"])
        clear_caches()

    def assert_refused(self, mutate: Callable[[dict[str, Any]], None] | None = None,
                       *, raw: str | None = None, fragment: str = "") -> None:
        consumers = (
            ("load", lambda: policy.load_policy("risk-features")),
            ("assess", lambda: risk_features.assess_risk_features("Inspect OIDC")),
            ("classify", lambda: classify_work("Inspect OIDC")),
        )
        with copied_risk_policy(mutate, raw=raw):
            for name, consume in consumers:
                with self.subTest(consumer=name):
                    clear_caches()
                    try:
                        with self.assertRaises(SystemExit) as raised:
                            consume()
                        self.assertIn("policy/risk-features.yaml", str(raised.exception))
                        self.assertIn(fragment, str(raised.exception))
                        self.assertEqual(risk_features._policy.cache_info().currsize, 0)
                    finally:
                        clear_caches()

    def test_boolean_version_is_refused_after_a_real_positive(self) -> None:
        self.assert_refused(lambda d: d.update(version=True), fragment="expected integer, found boolean")

    def test_version_is_exact_integer_token_one(self) -> None:
        for version in (False, 1.0, 2, "1", None):
            with self.subTest(version=version):
                self.assert_refused(lambda d: d.update(version=version), fragment="$.version")

    def test_closed_records_and_root_narrowing_metadata(self) -> None:
        mutations = (
            lambda d: d.update(validated_scope={"approved": True}),
            lambda d: d.update(unknown=True),
            lambda d: d["features"]["asset:authentication"].update(approved=True),
            lambda d: d["combinations"][0].update(approved=True),
        )
        for mutate in mutations:
            self.assert_refused(mutate, fragment="unexpected field")

    def test_required_fields(self) -> None:
        for field in ("version", "features"):
            with self.subTest(root_field=field):
                self.assert_refused(lambda d: d.pop(field), fragment="missing required field")
        for field in ("floor", "terms"):
            with self.subTest(feature_field=field):
                self.assert_refused(lambda d: d["features"]["asset:authentication"].pop(field),
                                    fragment="missing required field")
        for field in ("all", "floor"):
            with self.subTest(combination_field=field):
                self.assert_refused(lambda d: d["combinations"][0].pop(field), fragment="missing required field")

    def test_malformed_containers_and_records(self) -> None:
        mutations = (
            lambda d: d.update(features=[]),
            lambda d: d["features"].update({"asset:authentication": False}),
            lambda d: d.update(combinations={}),
            lambda d: d["combinations"].__setitem__(0, "high"),
            lambda d: d["combinations"][0].update(all="environment:production"),
        )
        for mutate in mutations:
            self.assert_refused(mutate, fragment="expected")

    def test_descriptions_are_strings(self) -> None:
        for value in (True, 7, [], {}, None):
            with self.subTest(value=value):
                self.assert_refused(lambda d: d.update(description=value), fragment="$.description")
                self.assert_refused(lambda d: d["features"]["asset:authentication"].update(label=value),
                                    fragment=".label")

    def test_arrays_and_nonempty_string_items(self) -> None:
        for field in ("terms", "experts"):
            for value in ("oidc", True, 7, {}, None, [""], [True], [7], [None], [[]], [{}]):
                with self.subTest(field=field, value=value):
                    self.assert_refused(lambda d: d["features"]["asset:authentication"].update({field: value}),
                                        fragment=f".{field}")
        for value in (True, 7, {}, None, [""], [True], [7], [None], [[]], [{}]):
            with self.subTest(combination_all=value):
                self.assert_refused(lambda d: d["combinations"][0].update(all=value), fragment=".all")

    def test_unknown_floors(self) -> None:
        for value in ("lowest", True, 1, None):
            with self.subTest(floor=value):
                self.assert_refused(lambda d: d["features"]["asset:authentication"].update(floor=value),
                                    fragment=".floor")
                self.assert_refused(lambda d: d["combinations"][0].update(floor=value), fragment=".floor")

    def test_duplicate_keys_and_numeric_tokens(self) -> None:
        raw = json.dumps(self.document)
        cases = [
            (raw.replace('"version": 1', '"version": 1, "version": 1', 1), "duplicate key 'version'"),
            (raw.replace('"floor": "medium"', '"floor": "medium", "floor": "high"', 1), "duplicate key 'floor'"),
        ]
        for token in ("NaN", "Infinity", "-Infinity", "1e309", "1" + "0" * 400):
            cases.append((raw.replace('"version": 1', '"version": ' + token, 1), "not JSON-compatible YAML"))
        for text, fragment in cases:
            with self.subTest(raw=text[:60], fragment=fragment):
                self.assertNotEqual(text, raw)
                self.assert_refused(raw=text, fragment=fragment)

    def test_non_object_root(self) -> None:
        for raw in ("[]", "true", "1", "null", '"risk"'):
            with self.subTest(raw=raw):
                self.assert_refused(raw=raw, fragment="top-level object")

    def test_configuration_refusal_class_and_early_narrowing_precedence(self) -> None:
        with copied_risk_policy(lambda d: d.update(version=True)):
            with self.assertRaises(PolicySchemaError):
                policy.load_policy("risk-features")
            for arguments in ({"risk_scope": {}}, {"risk_evidence_dir": ""}):
                clear_caches()
                with self.subTest(arguments=arguments):
                    with self.assertRaisesRegex(CWOValidationError, risk_features.RISK_NARROWING_UNSUPPORTED):
                        classify_work("Inspect OIDC", **arguments)
                    self.assertEqual(policy._load_policy_cached.cache_info().currsize, 0)
                    self.assertEqual(risk_features._policy.cache_info().currsize, 0)

    def test_optional_metadata_empty_arrays_and_dynamic_ids(self) -> None:
        def mutate(document: dict[str, Any]) -> None:
            document.pop("description")
            document.pop("combinations")
            feature = document["features"].pop("action:rotation")
            feature.pop("label")
            feature.pop("experts")
            document["features"]["custom:rotation"] = feature
            document["features"]["action:destructive"]["experts"] = []
            document["features"]["action:destructive"]["terms"] = []
        with copied_risk_policy(mutate):
            self.assertNotIn("description", policy.load_policy("risk-features"))
            assessment = risk_features.assess_risk_features("Rotate notes")
            self.assertEqual(assessment.features, {"custom:rotation": ["rotate"]})
            self.assertEqual(assessment.floor, "low")
            self.assertEqual(assessment.required_experts, [])
            route = classify_work("Rotate notes")
            self.assertEqual(route["risk_assessment"]["floor"], "low")
            self.assertEqual(route["risk_assessment"]["required_experts"], [])
            self.assertFalse(route["operative_route"]["dispatch_authorized"])

    def test_all_current_risk_floors_are_accepted(self) -> None:
        schema = load_policy_schema("risk-features.schema.json")
        self.assertEqual(schema["properties"]["features"]["additionalProperties"]["properties"]["floor"]["enum"],
                         policy.RISK_ORDER)
        self.assertEqual(schema["properties"]["combinations"]["items"]["properties"]["floor"]["enum"],
                         policy.RISK_ORDER)
        for floor in ("low", "medium", "high", "critical"):
            with self.subTest(floor=floor):
                with copied_risk_policy(lambda d: d["features"]["action:rotation"].update(floor=floor)):
                    self.assertEqual(risk_features.assess_risk_features("Rotate notes").floor, floor)

    def test_benign_shape_and_unknown_expert_do_not_grant_authority(self) -> None:
        route = classify_work("Fix the typo in README", file_paths=["README.md"])
        self.assertEqual(route["risk_level"], "low")
        self.assertEqual(route["risk_assessment"]["features"], [])
        def mutate(document: dict[str, Any]) -> None:
            document["features"]["asset:authentication"]["experts"] = ["unknown-risk-expert"]
        with copied_risk_policy(mutate):
            assessment = risk_features.assess_risk_features("Inspect OIDC")
            self.assertEqual(assessment.floor, "high")
            self.assertEqual(assessment.required_experts, ["unknown-risk-expert"])
            route = classify_work("Inspect OIDC")
            self.assertEqual(route["risk_assessment"]["unmet_required_experts"],
                             [{"expert": "unknown-risk-expert", "reason": "not defined in the expert registry"}])
            self.assertFalse(route["operative_route"]["dispatch_authorized"])


if __name__ == "__main__":
    unittest.main()
