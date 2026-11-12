"""Current expert metadata is typed before routing; declarations grant no authority."""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

from cwo_core import policy, policy_schema, routing  # noqa: E402
from test_policy_schema import malformed_policy  # noqa: E402

NAME = "expert-registry"
REQUIRED = (
    "display_name", "discipline", "persona_file", "job_description_label",
    "aliases", "task_class", "review_stage", "default_risk", "preferred_executors",
    "file_path_patterns", "trigger_terms", "required_inputs", "output_contract",
    "acceptance_checks", "escalation_rules",
)
STRINGS = (
    "display_name", "discipline", "persona_file", "job_description_label",
    "task_class", "review_stage", "default_share_boundary", "gate_scope",
)
ARRAYS = (
    "aliases", "preferred_executors", "file_path_patterns", "trigger_terms",
    "required_inputs", "output_contract", "acceptance_checks", "escalation_rules",
)
OPTIONAL = ("validation_gate_required", "gate_scope", "default_share_boundary")
_MISSING = object()


def edit(path: tuple[str, ...], value: Any = _MISSING) -> Callable[[dict[str, Any]], None]:
    def mutate(document: dict[str, Any]) -> None:
        parent = document
        for key in path[:-1]:
            parent = parent[key]
        if value is _MISSING:
            del parent[path[-1]]
        else:
            parent[path[-1]] = copy.deepcopy(value)

    return mutate


class ExpertRegistrySchemaTests(unittest.TestCase):
    def tearDown(self) -> None:
        policy.clear_policy_cache()
        policy_schema.clear_schema_cache()

    @staticmethod
    def consumers() -> dict[str, Callable[[], Any]]:
        return {
            "load": lambda: policy.load_policy(NAME),
            "suffix": lambda: policy.load_policy(NAME + ".yaml"),
            "expert reader": lambda: routing.score_experts_v2(
                "Review a note.", policy.load_policy(NAME), requested_roles=["operator-calibrated"],
            ),
            "route": lambda: routing.classify_work(
                "Documentation review for internal example notes.", requested_roles=["documentation"],
                share_boundary="no-outside-sharing", local_ok=True, prefer_local=True,
            ),
        }

    def assert_current(self) -> None:
        policy.clear_policy_cache()
        policy_schema.clear_schema_cache()
        expected = json.loads((ROOT / "policy" / f"{NAME}.yaml").read_text(encoding="utf-8"))
        self.assertEqual(policy.load_policy(NAME), expected)
        self.assertEqual(policy.load_policy(NAME + ".yaml"), expected)
        for name, entry in expected["experts"].items():
            with self.subTest(expert=name):
                self.assertFalse(set(REQUIRED) - set(entry))
                self.assertFalse(set(entry) - set(REQUIRED) - set(OPTIONAL))
        self.assertIs(type(expected["defaults"]["acceptance_required"]), bool)
        self.assertIs(type(expected["experts"]["editor"]["validation_gate_required"]), bool)
        experts = routing.score_experts_v2(
            "Review a note.", policy.load_policy(NAME), requested_roles=["operator-calibrated"],
        )
        self.assertEqual(experts[0]["name"], "operator_calibrated_execution")
        self.assertEqual(experts[0]["persona_file"], expected["experts"]["operator_calibrated_execution"]["persona_file"])
        route = routing.classify_work(
            "Documentation review for internal example notes.",
            requested_roles=["documentation"], local_ok=True, prefer_local=True,
            share_boundary="no-outside-sharing",
        )
        self.assertEqual(route["route"], "local-worker")
        self.assertEqual(route["recommended_executor"], "local_openai_compatible_worker")
        self.assertIn("documentation", [entry["name"] for entry in route["ranked_experts"]])
        self.assertEqual(policy.resolve_executor_key("ordinary_unknown_executor"), "ordinary_unknown_executor")
        self.assertEqual(
            routing.score_experts_v2("zz unmatched", policy.load_policy(NAME), requested_roles=["ordinary-unknown-role"]),
            [],
        )
        fallback = routing.classify_work("zz unmatched", requested_roles=["ordinary-unknown-role"])
        self.assertIn("general_reasoning", [entry["name"] for entry in fallback["ranked_experts"]])

    def assert_refused(self, mutate: Callable[[dict[str, Any]], None] | None = None, *,
                       raw: str | None = None, fragment: str) -> None:
        try:
            self.assert_current()
            with malformed_policy(NAME, mutate, raw):
                for label, call in self.consumers().items():
                    with self.subTest(consumer=label):
                        policy.clear_policy_cache()
                        with self.assertRaises(SystemExit) as raised:
                            result = call()
                            self.fail(f"malformed expert registry was accepted; consumer returned {result!r}")
                        message = str(raised.exception)
                        self.assertIn("policy/expert-registry.yaml", message)
                        self.assertIn(fragment, message)
                        self.assertNotIn("Traceback", message)
                        if label in {"load", "suffix"}:
                            self.assertEqual(policy._load_policy_cached.cache_info().currsize, 0)
        finally:
            policy.clear_policy_cache()
            policy_schema.clear_schema_cache()


    def test_canonical_cache_and_defensive_copies(self) -> None:
        self.assert_current()
        policy.clear_policy_cache()
        first = policy.load_policy(NAME)
        self.assertEqual(policy.load_policy(NAME + ".yaml"), first)
        self.assertEqual(policy._load_policy_cached.cache_info().currsize, 1)
        first["experts"]["general_reasoning"]["aliases"].append("caller-only-alias")
        self.assertNotIn("caller-only-alias", policy.load_policy(NAME)["experts"]["general_reasoning"]["aliases"])

    def test_dynamic_names_and_text_remain_data(self) -> None:
        self.assert_current()
        future = copy.deepcopy(policy.load_policy(NAME)["experts"]["general_reasoning"])
        for field in STRINGS:
            future[field] = "future metadata: $(false); data"
        for field in ARRAYS:
            future[field] = ["future metadata: $(false); data"]
        future["validation_gate_required"] = False
        with malformed_policy(NAME, edit(("experts",), {"future_expert": future})):
            registry = policy.load_policy(NAME)
            self.assertEqual(registry["experts"], {"future_expert": future})
            scored = routing.score_experts_v2("zz unmatched", registry, requested_roles=["future_expert"])
            self.assertEqual(scored[0]["name"], "future_expert")
            for field in ("persona_file", "job_description_label", "default_share_boundary", "gate_scope"):
                self.assertEqual(scored[0][field], future[field])

    def test_optional_fields_and_empty_arrays_are_valid(self) -> None:
        self.assert_current()
        def mutate(document: dict[str, Any]) -> None:
            for entry in document["experts"].values():
                for field in OPTIONAL:
                    entry.pop(field, None)
                for field in ARRAYS:
                    entry[field] = []
            document["defaults"]["acceptance_required"] = False
        with malformed_policy(NAME, mutate):
            registry = policy.load_policy(NAME)
            self.assertIs(registry["defaults"]["acceptance_required"], False)
            for entry in registry["experts"].values():
                self.assertFalse(set(OPTIONAL) & set(entry))
                for field in ARRAYS:
                    self.assertEqual(entry[field], [])

    def test_dynamic_boundary_names_and_known_risks_remain_valid(self) -> None:
        for risk in policy.RISK_ORDER:
            with self.subTest(risk=risk):
                self.assert_current()
                def mutate(document: dict[str, Any]) -> None:
                    document["defaults"]["default_share_boundary"] = "future-boundary"
                    document["experts"]["general_reasoning"].update(default_risk=risk, default_share_boundary="future-boundary")
                with malformed_policy(NAME, mutate):
                    registry = policy.load_policy(NAME)
                    self.assertEqual(registry["experts"]["general_reasoning"]["default_risk"], risk)
                    self.assertEqual(registry["defaults"]["default_share_boundary"], "future-boundary")

    def test_empty_expert_mapping_has_no_added_roster_requirement(self) -> None:
        self.assert_current()
        with malformed_policy(NAME, edit(("experts",), {})):
            self.assertEqual(policy.load_policy(NAME)["experts"], {})

    def test_version_and_schema_are_typed_constants(self) -> None:
        for value in (True, False, 2.0, 1, 3, "2", None):
            with self.subTest(version=value):
                self.assert_refused(edit(("version",), value), fragment="$.version")
        for value in (True, 1, "v2", None):
            with self.subTest(schema=value):
                self.assert_refused(edit(("schema",), value), fragment="$.schema")

    def test_flags_refuse_coercions(self) -> None:
        for path in (("defaults", "acceptance_required"), ("experts", "editor", "validation_gate_required")):
            for value in (1, 0, 1.0, "false", None, [], {}):
                with self.subTest(path=path, value=value):
                    self.assert_refused(edit(path, value), fragment=f"{path[-1]}: expected boolean")

    def test_all_scalar_metadata_is_typed(self) -> None:
        for prefix, fields in (
            (("defaults",), ("review_stage", "default_share_boundary")),
            (("experts", "general_reasoning"), STRINGS),
        ):
            for field in fields:
                for value in (True, 1, None, [], {}):
                    with self.subTest(path=prefix + (field,), value=value):
                        self.assert_refused(edit(prefix + (field,), value), fragment=f"{field}: expected string")

    def test_risk_uses_existing_risk_order(self) -> None:
        for value in (True, 1, None, [], {}, "lowest", "HIGH", ""):
            with self.subTest(risk=value):
                self.assert_refused(edit(("experts", "general_reasoning", "default_risk"), value), fragment="default_risk")

    def test_arrays_have_nonempty_string_items(self) -> None:
        for field in ARRAYS:
            for value in (1, True, "term", {}, None, [1], [True], [None], [""], [[]], [{}]):
                with self.subTest(field=field, value=value):
                    self.assert_refused(edit(("experts", "general_reasoning", field), value), fragment=field)

    def test_required_fields_at_each_closed_level(self) -> None:
        for prefix, fields in (
            ((), ("version", "schema", "defaults", "experts")),
            (("defaults",), ("review_stage", "default_share_boundary", "acceptance_required")),
            (("experts", "general_reasoning"), REQUIRED),
        ):
            for field in fields:
                with self.subTest(path=prefix + (field,)):
                    self.assert_refused(edit(prefix + (field,)), fragment=f"missing required field {field!r}")

    def test_closed_objects_and_typed_containers(self) -> None:
        for prefix in ((), ("defaults",), ("experts", "general_reasoning")):
            with self.subTest(extra=prefix):
                self.assert_refused(edit(prefix + ("unexpected",), True), fragment="unexpected: unexpected field")
        for path in (("defaults",), ("experts",), ("experts", "future_expert")):
            for value in (1, True, None, [], "expert"):
                with self.subTest(path=path, value=value):
                    self.assert_refused(edit(path, value), fragment="expected object")
        self.assert_refused(edit(("experts", "future_expert"), {}), fragment="missing required field")

    def test_strict_json_refusals_use_consumers(self) -> None:
        raw = (ROOT / "policy" / f"{NAME}.yaml").read_text(encoding="utf-8")
        duplicates = (
            ('"version": 2', '"version": 2, "version": 2'),
            ('"acceptance_required": true', '"acceptance_required": true, "acceptance_required": false'),
            ('"general_reasoning": {', '"general_reasoning": {}, "general_reasoning": {'),
            ('"validation_gate_required": true', '"validation_gate_required": true, "validation_gate_required": false'),
            ('"aliases": [', '"aliases": [], "aliases": ['),
        )
        for old, new in duplicates:
            with self.subTest(duplicate=old):
                self.assertIn(old, raw)
                self.assert_refused(raw=raw.replace(old, new, 1), fragment="duplicate key")
        for token in ("NaN", "Infinity", "-Infinity", "1e309", "1" + "0" * 400):
            with self.subTest(token=token[:16]):
                self.assert_refused(
                    raw=raw.replace('"version": 2', '"version": ' + token, 1),
                    fragment="is not JSON-compatible YAML",
                )
        for raw_document in ("[]", "true", "1", "null", '{"version":'):
            with self.subTest(document=raw_document):
                self.assert_refused(raw=raw_document, fragment="policy/expert-registry.yaml")


if __name__ == "__main__":
    unittest.main()
