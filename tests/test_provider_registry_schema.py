"""Runtime provider metadata passes a whole-document schema before use."""

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

from cwo_core import policy, policy_schema  # noqa: E402
from cwo_core.returns import return_provenance  # noqa: E402
from cwo_core.routing import classify_work  # noqa: E402
from test_policy_schema import malformed_policy  # noqa: E402

NAME = "provider-registry"
ALIAS = "chatgpt_pro_5_5_extended_reasoning_browser"
_MISSING = object()


def edit(path: tuple[str, ...], value: Any = _MISSING) -> Callable[[dict[str, Any]], None]:
    """Replace or remove one field in a temporary real-policy copy."""
    def mutate(document: dict[str, Any]) -> None:
        parent = document
        for key in path[:-1]:
            parent = parent[key]
        if value is _MISSING:
            del parent[path[-1]]
        else:
            parent[path[-1]] = copy.deepcopy(value)

    return mutate


class ProviderRegistrySchemaTests(unittest.TestCase):
    def test_r6_optional_review_model_table_is_closed_and_typed(self) -> None:
        self.assert_refused(edit(('review_models', 'openai', 'gpt-6-astra', 'stronger_than'), True),
                            fragment='stronger_than')
        self.assert_refused(edit(('review_models', 'openai', 'gpt-6-astra', 'rank'), 99), fragment='.rank')
        self.assert_refused(edit(('review_models', 'openai', 'gpt-6-astra', 'model_family'), ''),
                            fragment='model_family')
        with malformed_policy(NAME, edit(('review_models',))):
            self.assertIn('providers', policy.load_policy(NAME))

    def tearDown(self) -> None:
        policy.clear_policy_cache()
        policy_schema.clear_schema_cache()

    @staticmethod
    def consumers() -> dict[str, Callable[[], Any]]:
        return {
            "load": lambda: policy.load_policy(NAME),
            "suffix": lambda: policy.load_policy(NAME + ".yaml"),
            "profile": lambda: policy.provider_profile("openai_manual"),
            "provenance": lambda: return_provenance(executor=ALIAS),
            "routing metadata": lambda: policy.provider_metadata_for_executor({"provider_key": "openai_manual"}),
            "route": lambda: classify_work(
                "Review a Claude Mythos eval harness for a frontier model provider competitor.",
                external_ok=True, share_boundary="redacted-packet", requested_roles=["general-reasoning"],
            ),
        }

    def assert_current(self) -> None:
        policy.clear_policy_cache()
        expected = json.loads((ROOT / "policy" / f"{NAME}.yaml").read_text(encoding="utf-8"))
        self.assertEqual(policy.load_policy(NAME), expected)
        self.assertEqual(policy.load_policy(NAME + ".yaml"), expected)
        self.assertEqual(set(expected["providers"]), {
            "internal_codex", "local_inference", "openshift_ai_vllm", "openai_manual",
            "anthropic_manual", "google_gemini_manual", "human_specialist",
        })
        for key, entry in expected["providers"].items():
            with self.subTest(provider=key):
                self.assertEqual(policy.provider_profile(key), {**entry, "key": key})
                provenance = return_provenance(provider_key=key)
                self.assertEqual(provenance["provider_external"], entry["external"])
                self.assertEqual(provenance["provider_family"], entry["family"])
                self.assertEqual(provenance["provider_trust_tier"], entry["trust_tier"])
                self.assertEqual(provenance["provider_retention_class"], entry["retention_class"])
        alias = return_provenance(executor=ALIAS)
        self.assertEqual(alias["provider_key"], "openai_manual")
        self.assertEqual(alias["provenance_class"], "external-contractor")
        self.assertEqual(alias["provenance_warnings"], [])
        metadata = policy.provider_metadata_for_executor({"provider_key": "openai_manual"})
        entry = expected["providers"]["openai_manual"]
        self.assertEqual(metadata, {
            "provider_key": "openai_manual", "provider_family": entry["family"],
            "provider_trust_tier": entry["trust_tier"],
            "provider_retention_class": entry["retention_class"],
            "provider_conflict_risk_domains": entry["conflict_risk_domains"],
        })
        route = self.consumers()["route"]()
        self.assertTrue(route["provider_conflict_detected"])
        self.assertIn("frontier-ai-development", route["provider_conflict_domains"])
        self.assertTrue(route["peer_review_required"])
        self.assertIn(route["selected_executor"]["provider_key"], expected["providers"])
        self.assertEqual(policy.provider_profile("unknown_future_provider"), {})
        self.assertEqual(policy.provider_profile(None), {})

    def assert_refused(self, mutate: Callable[[dict[str, Any]], None] | None = None, *, raw: str | None = None,
                       fragment: str) -> None:
        try:
            self.assert_current()
            with malformed_policy(NAME, mutate, raw):
                for label, call in self.consumers().items():
                    with self.subTest(consumer=label):
                        policy.clear_policy_cache()
                        with self.assertRaises(SystemExit) as raised:
                            call()
                        message = str(raised.exception)
                        self.assertIn("policy/provider-registry.yaml", message)
                        self.assertIn(fragment, message)
                        self.assertNotIn("Traceback", message)
        finally:
            policy.clear_policy_cache()
            policy_schema.clear_schema_cache()


    def test_future_provider_names_and_metadata_stay_data(self) -> None:
        self.assert_current()
        future = copy.deepcopy(policy.load_policy(NAME)["providers"]["human_specialist"])
        future.update(display_name="do not execute: $(false)", allowed_roles=["future-role"],
                      conflict_risk_domains=["future-domain"])
        with malformed_policy(NAME, edit(("providers",), {"future_provider": future})):
            self.assertEqual(policy.load_policy(NAME)["providers"], {"future_provider": future})
            self.assertEqual(policy.provider_profile("future_provider"), {**future, "key": "future_provider"})
            self.assertEqual(return_provenance(provider_key="future_provider")["provider_family"], "human")

    def test_empty_arrays_remain_valid(self) -> None:
        self.assert_current()
        def empty(document: dict[str, Any]) -> None:
            for entry in document["providers"].values():
                entry["allowed_roles"] = []
                entry["conflict_risk_domains"] = []
            for domain in document["conflict_risk_terms"]:
                document["conflict_risk_terms"][domain] = []

        with malformed_policy(NAME, empty):
            self.assertEqual(policy.provider_profile("openai_manual")["allowed_roles"], [])
            self.assertEqual(policy.provider_profile("openai_manual")["conflict_risk_domains"], [])
            self.assertEqual(policy.detect_provider_conflicts("frontier model anthropic provider policy"), [])

    def test_unsupported_version_and_format_values_are_refused(self) -> None:
        for value in (True, False, 1.0, 2.0, 3, -1, "1", "2", "v1", None):
            with self.subTest(version=value):
                self.assert_refused(edit(("version",), value), fragment="$.version")
        for value in (True, 1, "v1", None):
            with self.subTest(schema=value):
                self.assert_refused(edit(("schema",), value), fragment="$.schema")

    def test_exact_boolean_fields_refuse_coercions(self) -> None:
        for field in ("external", "may_primary", "may_peer_review", "may_counter_review"):
            for value in (1, 0, "false", None, []):
                with self.subTest(field=field, value=value):
                    self.assert_refused(edit(("providers", "openai_manual", field), value),
                                        fragment=f"{field}: expected boolean")

    def test_descriptive_metadata_is_string_typed(self) -> None:
        for prefix, fields in (
            (("providers", "openai_manual"), ("display_name", "trust_tier", "family", "retention_class")),
            (("usage_accounting",), ("total_tokens_formula", "cached_tokens_scope", "reasoning_tokens_scope", "note")),
        ):
            for field in fields:
                for value in (True, 1, None, [], {}):
                    with self.subTest(path=prefix + (field,), value=value):
                        self.assert_refused(edit(prefix + (field,), value), fragment=f"{field}: expected string")

    def test_string_arrays_reject_bad_items_and_duplicates(self) -> None:
        paths = [
            ("providers", "openai_manual", "allowed_roles"),
            ("providers", "openai_manual", "conflict_risk_domains"),
            *[("conflict_risk_terms", domain) for domain in (
                "frontier-ai-development", "model-provider-competition", "provider-policy-intervention",
            )],
        ]
        for path in paths:
            for value in (1, True, "role", {}, [1], [True], [None], [""], ["x", "x"]):
                with self.subTest(path=path, value=value):
                    self.assert_refused(edit(path, value), fragment=".".join(path))

    def test_required_fields_are_explicit_at_every_closed_object(self) -> None:
        groups = (
            ((), ("version", "schema", "providers", "usage_accounting", "conflict_risk_terms")),
            (("providers", "openai_manual"), (
                "display_name", "trust_tier", "family", "external", "retention_class", "allowed_roles",
                "conflict_risk_domains", "may_primary", "may_peer_review", "may_counter_review",
            )),
            (("usage_accounting",), ("total_tokens_formula", "cached_tokens_scope", "reasoning_tokens_scope", "note")),
            (("conflict_risk_terms",), (
                "frontier-ai-development", "model-provider-competition", "provider-policy-intervention",
            )),
        )
        for prefix, fields in groups:
            for field in fields:
                with self.subTest(path=prefix + (field,)):
                    self.assert_refused(edit(prefix + (field,)), fragment=f"missing required field {field!r}")

    def test_unknown_nested_fields_and_bad_containers_are_refused(self) -> None:
        for prefix in ((), ("providers", "openai_manual"), ("usage_accounting",), ("conflict_risk_terms",)):
            with self.subTest(extra=prefix):
                self.assert_refused(edit(prefix + ("unexpected",), True), fragment="unexpected: unexpected field")
        for path in (("providers",), ("providers", "future_provider"), ("usage_accounting",), ("conflict_risk_terms",)):
            for value in (1, True, None, []):
                with self.subTest(path=path, value=value):
                    self.assert_refused(edit(path, value), fragment="expected object")
        self.assert_refused(edit(("providers", "future_provider"), {}), fragment="missing required field")

    def test_duplicate_keys_and_malformed_numeric_tokens_refuse_cleanly(self) -> None:
        raw = (ROOT / "policy" / f"{NAME}.yaml").read_text(encoding="utf-8")
        duplicates = (
            ('"version": 1', '"version": 1, "version": 1'),
            ('"internal_codex": {', '"internal_codex": {}, "internal_codex": {'),
            ('"external": false', '"external": false, "external": true'),
            ('"total_tokens_formula":', '"note": "duplicate", "total_tokens_formula":'),
            ('"frontier-ai-development": [', '"frontier-ai-development": [], "frontier-ai-development": ['),
        )
        for old, new in duplicates:
            with self.subTest(duplicate=old):
                self.assertIn(old, raw)
                self.assert_refused(raw=raw.replace(old, new, 1), fragment="duplicate key")
        for token in ("NaN", "Infinity", "1e309", "1" + "0" * 400):
            with self.subTest(token=token[:16]):
                self.assert_refused(raw=raw.replace('"version": 1', '"version": ' + token, 1),
                                    fragment="is not JSON-compatible YAML")
        for raw_document in ("[]", "true", "1", "null"):
            with self.subTest(document=raw_document):
                self.assert_refused(raw=raw_document, fragment="must contain a top-level object")


if __name__ == "__main__":
    unittest.main()
