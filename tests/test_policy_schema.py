"""Current policy documents are schema-checked before any consumer reads them.

The consumer tests use only cwo_core.policy and the return-risk helpers, so they
also run against a tree without cwo_core.policy_schema and show what such a tree
accepts. Subset and comparison tests import the validator inside each test.
"""

from __future__ import annotations

import copy
import importlib
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, NamedTuple
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import policy, return_common, return_risk  # noqa: E402

SCHEMA_POLICIES = ('qualification-target', 'contracting-controls',
 'model-identity-scope',
 'outbound-screening',
 'peer-review-policy',
 'return-tripwires',
 'provider-registry',
 'routing-policy',
 'synthesis-policy',
 'harness-registry',
 'expert-registry',
 'risk-features',
 'share-boundaries',
 'acceptance-policy',
 'zero-trust-consensus-policy',
 'executor-registry',
 'execution-environments',
 'model-profiles',
 'access-profiles',
 'native-worker-execution')


def _schema_module() -> Any:
    return importlib.import_module("cwo_core.policy_schema")


def _read(name: str) -> dict[str, Any]:
    return json.loads((ROOT / "policy" / f"{name}.yaml").read_text(encoding="utf-8"))


class PolicyRefusal(NamedTuple):
    original: str
    policy_name: str
    mutate: Callable[[dict[str, Any]], None] | None
    consumer: Callable[[], Any]
    fragments: tuple[str, ...]
    raw: str | None = None


@contextmanager
def malformed_policy(name: str, mutate: Callable[[dict[str, Any]], None] | None = None, raw: str | None = None) -> Iterator[Path]:
    """A copy of the real policy directory in which one document is changed."""
    with tempfile.TemporaryDirectory() as tmpdir:
        policy_dir = Path(tmpdir) / "policy"
        shutil.copytree(ROOT / "policy", policy_dir)
        if raw is None:
            document = _read(name)
            if mutate is not None:
                mutate(document)
            raw = json.dumps(document, indent=2)
        (policy_dir / f"{name}.yaml").write_text(raw, encoding="utf-8")
        policy.clear_policy_cache()
        try:
            with mock.patch.object(policy, "POLICY_DIR", policy_dir):
                yield policy_dir
        finally:
            policy.clear_policy_cache()


class MalformedPolicyAtConsumersTests(unittest.TestCase):
    """Negative regressions: each malformed document must stop its consumer, not change its answer."""

    def tearDown(self) -> None:
        policy.clear_policy_cache()

    def assert_refused(self, call: Callable[[], Any], *fragments: str) -> str:
        with self.assertRaises(SystemExit) as raised:
            result = call()
            self.fail(f"malformed policy was accepted; consumer returned {result!r}")
        message = str(raised.exception)
        for fragment in fragments:
            self.assertIn(fragment, message)
        return message

    def test_malformed_policy_consumer_refusal_rows(self) -> None:
        def rename(document: dict[str, Any]) -> None:
            document["required_for_risk_level"] = document.pop("required_for_risk_levels")

        raw = (ROOT / "policy" / "contracting-controls.yaml").read_text(encoding="utf-8").replace(
            '"unexpected_script_ratio": 0.2', '"unexpected_script_ratio": NaN'
        )
        self.assertIn("NaN", raw)
        rows = (
            PolicyRefusal("test_boolean_minimum_peer_reviews_does_not_waive_peer_review", "peer-review-policy",
                          lambda d: d["defaults"].update(minimum_peer_reviews=False),
                          lambda: policy.validate_peer_review_controls(peer_reviews=[]),
                          ("peer-review-policy.yaml", "minimum_peer_reviews", "expected integer, found boolean")),
            PolicyRefusal("test_zero_minimum_peer_reviews_is_refused", "peer-review-policy",
                          lambda d: d["defaults"].update(minimum_peer_reviews=0),
                          lambda: policy.validate_peer_review_controls(peer_reviews=[]), ("must be at least 1",)),
            PolicyRefusal("test_misspelled_risk_level_key_does_not_drop_critical_peer_review", "peer-review-policy", rename,
                          lambda: policy.route_requires_peer_review(
                              route="internal-worker", risk="critical", share_boundary="no-outside-sharing",
                              provider_conflict_domains=[]),
                          ("missing required field 'required_for_risk_levels'", "required_for_risk_level: unexpected field")),
            PolicyRefusal("test_string_boolean_is_refused", "peer-review-policy",
                          lambda d: d["defaults"].update(provider_diversity_required="false"), policy.peer_review_policy,
                          ("provider_diversity_required", "expected boolean, found string")),
            PolicyRefusal("test_boolean_sabotage_weight_is_refused", "contracting-controls",
                          lambda d: d["sabotage_policy"]["signal_weights"].update(prompt_injection=True),
                          return_risk.sabotage_signal_weights, ("prompt_injection", "expected integer, found boolean")),
            PolicyRefusal("test_string_sabotage_weight_is_refused", "contracting-controls",
                          lambda d: d["sabotage_policy"]["signal_weights"].update(fabricated_evidence="35"),
                          return_risk.sabotage_signal_weights, ("fabricated_evidence", "found string")),
            PolicyRefusal("test_out_of_range_malpractice_weight_is_refused", "contracting-controls",
                          lambda d: d["malpractice_policy"]["signal_weights"].update(missing_evidence=-5),
                          return_common.malpractice_signal_weights, ("missing_evidence", "must be at least 0")),
            PolicyRefusal("test_non_finite_language_ratio_is_refused", "contracting-controls", None,
                          policy.load_contracting_controls, ("non-finite number NaN",), raw),
            PolicyRefusal("test_empty_local_worker_allowlist_is_refused", "routing-policy",
                          lambda d: d["local_worker"].update(allowed_task_classes=[]),
                          lambda: policy.load_policy("routing-policy"), ("allowed_task_classes", "at least 1 items")),
            PolicyRefusal("test_unknown_default_risk_level_is_refused", "routing-policy",
                          lambda d: d["defaults"].update(risk_level="lowest"),
                          lambda: policy.load_policy("routing-policy"), ("defaults.risk_level", "must be one of")),
        )
        for row in rows:
            with self.subTest(original=row.original):
                with malformed_policy(row.policy_name, row.mutate, row.raw):
                    self.assert_refused(row.consumer, *row.fragments)

    def test_refusal_is_deterministic(self) -> None:
        def mutate(document: dict[str, Any]) -> None:
            document["defaults"].update(minimum_peer_reviews=True, extra=1)

        messages = []
        for _ in range(2):
            with malformed_policy("peer-review-policy", mutate):
                messages.append(self.assert_refused(policy.peer_review_policy))
        self.assertEqual(messages[0], messages[1])

    def test_current_policies_load_unchanged(self) -> None:
        policy.clear_policy_cache()
        for name in SCHEMA_POLICIES:
            with self.subTest(policy=name):
                self.assertEqual(policy.load_policy(name), _read(name))

    def test_effective_thresholds_are_unchanged(self) -> None:
        policy.clear_policy_cache()
        self.assertEqual(return_risk.sabotage_thresholds(), {"review": 20, "architect_escalation": 35, "quarantine": 50})
        self.assertEqual(return_risk.malpractice_thresholds(), {"review": 25, "reject": 60})
        self.assertEqual(policy.validate_peer_review_controls(peer_reviews=[])["valid"], False)

    def test_unexpected_threshold_field_is_refused(self) -> None:
        with malformed_policy(
            "contracting-controls", lambda d: d["sabotage_policy"]["thresholds"].update(quarantine_override=99)
        ):
            self.assert_refused(return_risk.sabotage_thresholds, "quarantine_override: unexpected field")

class FormerlyUnvalidatedPoliciesAtConsumersTests(unittest.TestCase):
    """Policies with a recorded "none" boundary reach no consumer unless their schema matches."""

    def setUp(self) -> None:
        from cwo_core import outbound_screen, return_tripwires

        self.caches = (outbound_screen._rules, return_tripwires._policy)
        self.clear()

    def tearDown(self) -> None:
        self.clear()

    def clear(self) -> None:
        policy.clear_policy_cache()
        for cached in self.caches:
            cached.cache_clear()

    def assert_refused_at(self, name: str, mutate: Callable[[dict[str, Any]], None], call: Callable[[], Any],
                          *fragments: str) -> None:
        with malformed_policy(name, mutate):
            self.clear()
            with self.assertRaises(SystemExit) as raised:
                result = call()
                self.fail(f"malformed policy/{name}.yaml was accepted; consumer returned {result!r}")
        self.clear()
        message = str(raised.exception)
        self.assertIn(f"policy/{name}.yaml", message)
        for fragment in fragments:
            self.assertIn(fragment, message)

    def scan(self) -> Any:
        from cwo_core.return_tripwires import scan_return_tripwires

        return lambda: scan_return_tripwires("Please disable TLS verification for the deploy step.")

    def screen(self) -> Any:
        from cwo_core.outbound_screen import screen_outbound

        return lambda: screen_outbound("Summary of the plan.", surface="test")

    def synthesize(self) -> Any:
        from cwo_core.synthesis import recommend_model_synthesis

        return lambda: recommend_model_synthesis("Synthesize the model camps into one answer.", {})

    def test_return_tripwire_flags_and_patterns_are_typed(self) -> None:
        # bool("false") made a non-negatable rule negatable; str(7) made a number a pattern.
        self.assert_refused_at("return-tripwires", lambda d: d["rules"][0].update(negatable="false"), self.scan(),
                               "negatable", "expected boolean")
        self.assert_refused_at("return-tripwires", lambda d: d["rules"][0].update(pattern=7), self.scan(), "pattern")
        self.assert_refused_at("return-tripwires", lambda d: d["rules"][0].update(directve=True), self.scan(), "directve")
        self.assert_refused_at("return-tripwires", lambda d: d.update(rules=[]), self.scan(), "rules")

    def test_outbound_screen_rules_are_typed_and_non_empty(self) -> None:
        # int("20") accepted a string tail; an empty header list compiled to an empty alternation.
        self.assert_refused_at("outbound-screening", lambda d: d["token_prefixes"][0].update(min_tail="20"),
                               self.screen(), "min_tail")
        self.assert_refused_at("outbound-screening", lambda d: d.update(secret_headers=[]), self.screen(),
                               "secret_headers")
        self.assert_refused_at("outbound-screening", lambda d: d["pii"].update(ssn="maybe"), self.screen(), "ssn")
        self.assert_refused_at("outbound-screening", lambda d: d["entropy"].update(mixed_min_bits=True), self.screen(),
                               "mixed_min_bits")

    def test_synthesis_policy_is_typed(self) -> None:
        # int(True) read as one usable input; bool("false") allowed partial synthesis.
        self.assert_refused_at("synthesis-policy",
                               lambda d: d["partial_synthesis_policy"].update(minimum_usable_inputs=True),
                               self.synthesize(), "minimum_usable_inputs")
        self.assert_refused_at("synthesis-policy", lambda d: d["partial_synthesis_policy"].update(allow_partial="false"),
                               self.synthesize(), "allow_partial")
        self.assert_refused_at("synthesis-policy", lambda d: d.update(default_share_boundary="everyone"),
                               self.synthesize(), "default_share_boundary")

    def test_shipped_documents_still_reach_their_consumers(self) -> None:
        self.assertTrue(self.scan()())
        self.assertTrue(self.screen()().findings is not None)
        self.assertIn("recommended_mode", self.synthesize()())


class SchemaSubsetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ps = _schema_module()

    def test_unsupported_keywords_are_refused_not_ignored(self) -> None:
        for keyword, value in {
            "pattern": "^a$", "oneOf": [], "anyOf": [], "allOf": [], "not": {}, "$ref": "#", "$defs": {},
            "patternProperties": {}, "propertyNames": {}, "format": "uri", "exclusiveMinimum": 0, "maxLength": 1,
            "maxItems": 1, "minProperties": 1, "if": {}, "then": {}, "prefixItems": [], "contains": {},
            "dependentRequired": {}, "default": 1, "additionalProperty": False,
        }.items():
            with self.subTest(keyword=keyword):
                errors = self.ps.schema_errors({"type": "object", "additionalProperties": False, keyword: value})
                self.assertIn(f"#: unsupported schema keyword {keyword!r}", errors)

    def test_structural_omissions_are_refused(self) -> None:
        cases = {
            "object without additionalProperties": ({"type": "object"}, "must declare additionalProperties"),
            "array without items": ({"type": "array"}, "must declare items"),
            "node without type, enum or const": ({"minimum": 1}, "declares none of type, enum or const"),
            "undeclared required name": (
                {"type": "object", "additionalProperties": False, "required": ["a"]}, "'a' is not declared"),
            "unknown type": ({"type": "int"}, "/type"),
            "empty enum": ({"enum": []}, "/enum"),
            "duplicate enum values": ({"enum": [1, 1.0]}, "values must be distinct"),
            "boolean bound": ({"type": "integer", "minimum": True}, "/minimum: must be a number"),
            "nested unsupported keyword": (
                {"type": "object", "additionalProperties": False, "properties": {"a": {"type": "string", "pattern": "x"}}},
                "#/properties/a: unsupported schema keyword 'pattern'"),
        }
        for label, (schema, fragment) in cases.items():
            with self.subTest(case=label):
                self.assertTrue(any(fragment in error for error in self.ps.schema_errors(schema)), self.ps.schema_errors(schema))
        self.assertEqual(self.ps.schema_errors({"enum": [1, True]}), [])

    def test_json_types_are_not_python_types(self) -> None:
        validate = self.ps.validate_instance
        self.assertTrue(validate(True, {"type": "integer"}))
        self.assertTrue(validate(1.0, {"type": "integer"}))
        self.assertTrue(validate(False, {"type": "number"}))
        self.assertTrue(validate(float("nan"), {"type": "number"}))
        self.assertTrue(validate(float("inf"), {"type": "number"}))
        self.assertTrue(validate(True, {"enum": [1]}))
        self.assertTrue(validate(False, {"const": 0}))
        self.assertTrue(validate({"a": True}, {"const": {"a": 1}}))
        self.assertTrue(validate([1, 1.0], {"type": "array", "uniqueItems": True, "items": {"type": "number"}}))
        self.assertEqual(validate([1, True], {"type": "array", "uniqueItems": True, "items": {"type": ["integer", "boolean"]}}), [])
        self.assertEqual(validate(1, {"const": 1.0}), [])
        self.assertEqual(validate(2.5, {"type": "number", "minimum": 0, "maximum": 3}), [])

    def test_registered_schemas_are_whole_document_and_supported(self) -> None:
        self.assertEqual(
            set(self.ps.POLICY_SCHEMAS), {f"{name}.yaml" for name in SCHEMA_POLICIES}
        )
        for filename, schema_name in self.ps.POLICY_SCHEMAS.items():
            with self.subTest(schema=schema_name):
                schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
                self.assertEqual(self.ps.schema_errors(schema), [])
                self.assertIs(schema["additionalProperties"], False)
                self.assertEqual(self.ps.policy_document_errors(filename, _read(filename[:-5])), [])

    def test_schema_with_unsupported_keyword_cannot_be_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            schema_dir = Path(tmpdir)
            (schema_dir / "x.schema.json").write_text(json.dumps({"type": "integer", "multipleOf": 2}), encoding="utf-8")
            (schema_dir / "dup.schema.json").write_text('{"type": "integer", "type": "string"}', encoding="utf-8")
            self.ps.clear_schema_cache()
            try:
                with mock.patch.object(self.ps, "SCHEMA_DIR", schema_dir):
                    with self.assertRaises(SystemExit) as raised:
                        self.ps.load_policy_schema("x.schema.json")
                    self.assertIn("unsupported schema keyword 'multipleOf'", str(raised.exception))
                    with self.assertRaises(SystemExit) as raised:
                        self.ps.load_policy_schema("dup.schema.json")
                    self.assertIn("duplicate key 'type'", str(raised.exception))
            finally:
                self.ps.clear_schema_cache()

    def test_missing_schema_file_fails_closed_at_load(self) -> None:
        # A copy without the schema file must refuse the policy, not skip validation.
        with tempfile.TemporaryDirectory() as tmpdir:
            self.ps.clear_schema_cache()
            policy.clear_policy_cache()
            try:
                with mock.patch.object(self.ps, "SCHEMA_DIR", Path(tmpdir)):
                    with self.assertRaises(SystemExit) as raised:
                        policy.load_policy("peer-review-policy")
                self.assertIn("schemas/peer-review-policy.schema.json cannot be read as strict JSON", str(raised.exception))
            finally:
                self.ps.clear_schema_cache()
                policy.clear_policy_cache()

    def test_every_policy_has_a_recorded_validation_boundary(self) -> None:
        present = {path.name for path in (ROOT / "policy").glob("*.yaml")}
        self.assertEqual(set(self.ps.POLICY_VALIDATION_BOUNDARIES), present)
        for name, (kind, detail) in self.ps.POLICY_VALIDATION_BOUNDARIES.items():
            with self.subTest(policy=name):
                self.assertIn(kind, {"schema", "repository-check", "consumer-check", "partial", "none"})
                self.assertTrue(detail)
                self.assertEqual(kind == "schema", name in self.ps.POLICY_SCHEMAS)

    def test_repository_validator_reports_a_policy_without_a_boundary(self) -> None:
        import validate_repository

        with tempfile.TemporaryDirectory() as tmpdir:
            policy_dir = Path(tmpdir)
            shutil.copytree(ROOT / "policy", policy_dir, dirs_exist_ok=True)
            (policy_dir / "new-policy.yaml").write_text('{"version": 1}', encoding="utf-8")
            peer = json.loads((policy_dir / "peer-review-policy.yaml").read_text(encoding="utf-8"))
            peer["defaults"]["minimum_peer_reviews"] = False
            (policy_dir / "peer-review-policy.yaml").write_text(json.dumps(peer), encoding="utf-8")
            errors: list[str] = []
            validate_repository.validate_policy_validation_boundaries(errors, policy_dir)
        self.assertIn("policy/new-policy.yaml has no recorded validation boundary in cwo_core.policy_schema", errors)
        self.assertTrue(any("peer-review-policy.yaml does not match" in error and "minimum_peer_reviews" in error for error in errors))
        clean: list[str] = []
        validate_repository.validate_policy_validation_boundaries(clean)
        self.assertEqual(clean, [])


class PolicyIdentityTests(unittest.TestCase):
    """A policy has one identity for the file read, the schema lookup and the cache; no spelling skips the schema."""

    def tearDown(self) -> None:
        policy.clear_policy_cache()

    @staticmethod
    def spellings(name: str, policy_dir: Path) -> dict[str, Any]:
        """Every non-canonical way to name the file at ``policy_dir/<name>.yaml``."""
        return {
            "dot slash": f"./{name}",
            "dot slash with suffix": f"./{name}.yaml",
            "parent then policy": f"../policy/{name}",
            "absolute path": str(policy_dir / f"{name}.yaml"),
            "absolute path without suffix": str(policy_dir / name),
            "upper case": name.upper(),
            "mixed case": name[:1].upper() + name[1:],
            "mixed case suffix": f"{name}.YAML",
            "trailing slash": f"{name}/",
            "doubled suffix": f"{name}.yaml.yaml",
            "surrounding space": f" {name} ",
            "path object": policy_dir / f"{name}.yaml",
        }

    def assert_no_document(self, spelling: Any) -> None:
        with self.assertRaises(SystemExit) as raised:
            result = policy.load_policy(spelling)
            self.fail(f"load_policy({spelling!r}) returned a document: {sorted(result)[:3]!r}")
        self.assertTrue(str(raised.exception))

    def test_malformed_document_is_refused_through_every_spelling(self) -> None:
        mutations = {
            "peer-review-policy": lambda d: d["defaults"].update(minimum_peer_reviews=False),
            "contracting-controls": lambda d: d["sabotage_policy"]["signal_weights"].update(prompt_injection=True),
            "routing-policy": lambda d: d["local_worker"].update(allowed_task_classes=[]),
            "model-identity-scope": lambda d: d.update(authority="all"),
        }
        for name, mutate in mutations.items():
            with malformed_policy(name, mutate) as policy_dir:
                self.assertTrue((policy_dir / f"{name}.yaml").is_file())
                for label, spelling in self.spellings(name, policy_dir).items():
                    with self.subTest(policy=name, spelling=label):
                        self.assert_no_document(spelling)
                for spelling in (name, f"{name}.yaml"):
                    with self.subTest(policy=name, spelling=spelling):
                        with self.assertRaises(SystemExit) as raised:
                            policy.load_policy(spelling)
                        self.assertIn(f"policy/{name}.yaml does not match", str(raised.exception))

    def test_missing_schema_is_refused_through_every_spelling(self) -> None:
        ps = _schema_module()
        for name in SCHEMA_POLICIES:
            with tempfile.TemporaryDirectory() as tmpdir:
                ps.clear_schema_cache()
                policy.clear_policy_cache()
                try:
                    with mock.patch.object(ps, "SCHEMA_DIR", Path(tmpdir)):
                        for label, spelling in {
                            "bare": name, "suffix": f"{name}.yaml", **self.spellings(name, ROOT / "policy")
                        }.items():
                            with self.subTest(policy=name, spelling=label):
                                self.assert_no_document(spelling)
                        with self.assertRaises(SystemExit) as raised:
                            policy.load_policy(name)
                        self.assertIn("schemas/" + ps.POLICY_SCHEMAS[f"{name}.yaml"] + " cannot be read as strict JSON", str(raised.exception))
                finally:
                    ps.clear_schema_cache()
                    policy.clear_policy_cache()

    def test_valid_document_is_not_readable_by_path(self) -> None:
        # A path is refused even when the file it names is valid: identity comes only from the bare name.
        policy.clear_policy_cache()
        for label, spelling in self.spellings("synthesis-policy", ROOT / "policy").items():
            with self.subTest(spelling=label):
                with self.assertRaises(SystemExit) as raised:
                    policy.load_policy(spelling)
                self.assertNotIn("missing policy file", str(raised.exception))
        self.assertEqual(policy.load_policy("synthesis-policy"), policy.load_policy("synthesis-policy.yaml"))

    def test_cache_key_is_the_canonical_filename(self) -> None:
        policy.clear_policy_cache()
        policy.load_policy("peer-review-policy")
        policy.load_policy("peer-review-policy.yaml")
        self.assertEqual(policy._load_policy_cached.cache_info().currsize, 1)
        for key in ("peer-review-policy", "./peer-review-policy.yaml", str(ROOT / "policy" / "peer-review-policy.yaml")):
            with self.subTest(key=key):
                with self.assertRaises(SystemExit):
                    policy._load_policy_cached(key)
        self.assertEqual(policy._load_policy_cached.cache_info().currsize, 1)

    def test_schema_lookup_refuses_a_non_canonical_filename(self) -> None:
        ps = _schema_module()
        malformed = _read("peer-review-policy")
        malformed["defaults"]["minimum_peer_reviews"] = False
        self.assertTrue(ps.policy_document_errors("peer-review-policy.yaml", malformed))
        for filename in ("./peer-review-policy.yaml", "Peer-Review-Policy.yaml", "peer-review-policy", "/x/peer-review-policy.yaml"):
            with self.subTest(filename=filename):
                with self.assertRaises(SystemExit):
                    ps.policy_document_errors(filename, malformed)
                with self.assertRaises(SystemExit):
                    ps.validate_policy_document(filename, malformed)


class NumericOverflowTests(unittest.TestCase):
    """Number tokens that overflow are refused at parse time, with or without a schema."""

    def tearDown(self) -> None:
        policy.clear_policy_cache()

    def test_overflow_in_a_policy_without_a_schema_is_refused(self) -> None:
        # Remove only the native registration in this disposable test context.
        ps = _schema_module()
        self.assertEqual(ps.POLICY_SCHEMAS["native-worker-execution.yaml"], "native-worker-execution-policy.schema.json")
        self.addCleanup(policy.clear_policy_cache)
        self.addCleanup(ps.clear_schema_cache)
        unregistered = {name: schema for name, schema in ps.POLICY_SCHEMAS.items() if name != "native-worker-execution.yaml"}
        self.enterContext(mock.patch.dict(ps.POLICY_SCHEMAS, unregistered, clear=True))
        policy.clear_policy_cache()
        ps.clear_schema_cache()
        self.assertNotIn("native-worker-execution.yaml", ps.POLICY_SCHEMAS)
        self.assertEqual(policy.load_policy("native-worker-execution"), _read("native-worker-execution"))
        for token in ("1e309", "-1e309", "1" + "0" * 400):
            document = _read("native-worker-execution")
            document["zz_nested"] = {"values": [1, {"limit": "__OVERFLOW__"}]}
            raw = json.dumps(document, indent=2).replace('"__OVERFLOW__"', token)
            with self.subTest(token=token[:12]):
                with malformed_policy("native-worker-execution", raw=raw):
                    with self.assertRaises(SystemExit) as raised:
                        result = policy.load_policy("native-worker-execution")
                        self.fail(f"overflow accepted: {result.get('zz_nested')!r}")
                    message = str(raised.exception)
                    self.assertIn("native-worker-execution.yaml is not JSON-compatible YAML", message)
                    self.assertTrue(
                        "overflows to a non-finite value" in message or "outside the finite number range" in message, message
                    )

    def test_overflow_in_a_covered_policy_is_refused_at_parse(self) -> None:
        raw = (ROOT / "policy" / "contracting-controls.yaml").read_text(encoding="utf-8").replace(
            '"unexpected_script_ratio": 0.2', '"unexpected_script_ratio": 1e309'
        )
        self.assertIn("1e309", raw)
        with malformed_policy("contracting-controls", raw=raw):
            with self.assertRaises(SystemExit) as raised:
                policy.load_contracting_controls()
            self.assertIn("overflows to a non-finite value", str(raised.exception))

    def test_finite_extremes_still_parse(self) -> None:
        ps = _schema_module()
        self.assertEqual(ps.strict_json_loads('{"x": 1.7976931348623157e308}')["x"], 1.7976931348623157e308)
        self.assertEqual(ps.strict_json_loads('{"x": -1.7976931348623157e308}')["x"], -1.7976931348623157e308)
        self.assertEqual(ps.strict_json_loads('{"x": 1e-400}')["x"], 0.0)
        self.assertEqual(ps.strict_json_loads('{"x": 12345678901234567890}')["x"], 12345678901234567890)
        self.assertEqual(ps.strict_json_loads('{"x": 0.2, "y": 35}'), {"x": 0.2, "y": 35})


    def test_overflowing_numbers_are_refused(self) -> None:
        ps = _schema_module()
        huge_integer = "1" + "0" * 400
        for text in (
            '{"ratio": 1e309}',
            '{"ratio": -1e309}',
            '{"ratio": 1.5E+400}',
            '{"a": {"b": [0.5, {"c": 1e400}]}}',
            '[1e309]',
            '1e309',
            '{"n": ' + huge_integer + '}',
            '{"a": [{"n": -' + huge_integer + '}]}',
        ):
            with self.subTest(text=text[:40]):
                with self.assertRaises(ValueError):
                    ps.strict_json_loads(text)


def _leaf_mutations(document: Any, path: tuple[Any, ...] = ()) -> Iterator[tuple[str, tuple[Any, ...], Any, bool]]:
    """(label, path, replacement, integral_float) for every leaf; None replacement path means delete."""
    if isinstance(document, dict):
        yield ("unexpected field", path + ("zz_unexpected",), 1, False)
        for key, value in document.items():
            yield ("removed field", path + (key,), _DELETE, False)
            yield from _leaf_mutations(value, path + (key,))
        return
    if isinstance(document, list):
        if document:
            yield ("duplicated item", path + (len(document),), copy.deepcopy(document[0]), False)
            yield ("emptied list", path, [], False)
            yield from _leaf_mutations(document[0], path + (0,))
        return
    if type(document) is bool:
        yield ("bool as integer", path, int(document), False)
        yield ("bool as string", path, str(document).lower(), False)
    elif type(document) is int:
        yield ("integer as bool", path, document != 0, False)
        yield ("integer as string", path, str(document), False)
        yield ("integer as integral float", path, float(document), True)
        yield ("integer far above", path, document + 100000, False)
        yield ("integer far below", path, document - 100000, False)
    elif type(document) is float:
        yield ("number as string", path, str(document), False)
        yield ("number above one", path, document + 2, False)
    elif type(document) is str:
        yield ("string as integer", path, 7, False)
        yield ("empty string", path, "", False)
        yield ("changed string", path, document + "-changed", False)
    yield ("null", path, None, False)


_DELETE = object()


def _apply(document: str, path: tuple[Any, ...], replacement: Any) -> Any:
    # Each case still owns a complete JSON tree. Parse the unchanged document
    # snapshot rather than walking the same Python containers for every case.
    result = json.loads(document)
    if not path:
        return replacement
    parent = result
    for step in path[:-1]:
        parent = parent[step]
    last = path[-1]
    if replacement is _DELETE:
        del parent[last]
    elif isinstance(parent, list) and last == len(parent):
        parent.append(replacement)
    else:
        parent[last] = replacement
    return result


def _systematic_cases(document: dict[str, Any]) -> Iterator[tuple[str, Any, bool]]:
    # Freeze the complete plan before either validator sees the original input.
    # Stream independent full trees instead of retaining thousands of them.
    snapshot = json.dumps(document)
    mutations = tuple(_leaf_mutations(document))
    yield ("original", document, False)
    for label, path, replacement, integral_float in mutations:
        yield (f"{label} at {'/'.join(map(str, path))}", _apply(snapshot, path, replacement), integral_float)


class IndependentValidatorTests(unittest.TestCase):
    """The bounded validator agrees with jsonschema (test-only) and is never more permissive."""

    def setUp(self) -> None:
        self.ps = _schema_module()
        try:
            import jsonschema
        except ImportError as exc:  # pragma: no cover - requirements-test.txt pins it
            self.fail(f"jsonschema from requirements-test.txt is required: {exc}")
        self.jsonschema = jsonschema

    def compare(self, schema: dict[str, Any], cases: Iterable[tuple[str, Any, bool]]) -> dict[str, int]:
        self.jsonschema.Draft202012Validator.check_schema(schema)
        reference = self.jsonschema.Draft202012Validator(schema)
        totals = {"cases": 0, "accepted": 0, "rejected": 0, "stricter": 0}
        for label, value, integral_float in cases:
            bounded_ok = not self.ps.validate_instance(value, schema)
            reference_ok = reference.is_valid(value)
            totals["cases"] += 1
            totals["accepted" if bounded_ok else "rejected"] += 1
            if bounded_ok:
                self.assertTrue(reference_ok, f"bounded validator accepts what jsonschema rejects: {label}")
            elif reference_ok:
                # The only declared divergence: 1.0 is a JSON Schema integer but not a policy integer.
                self.assertTrue(integral_float, f"bounded validator rejects what jsonschema accepts: {label}")
                totals["stricter"] += 1
        return totals

    def test_permissive_counterexamples(self) -> None:
        cases = [
            ({"type": "integer"}, True, False),
            ({"type": "integer"}, 1.0, True),
            ({"type": "number"}, False, False),
            ({"enum": [1, 2]}, True, False),
            ({"enum": [0]}, False, False),
            ({"const": 1}, True, False),
            ({"const": {"a": 1}}, {"a": True}, False),
            ({"const": [0]}, [False], False),
            ({"type": "array", "uniqueItems": True, "items": {"type": ["integer", "boolean"]}}, [1, True], False),
            ({"type": "array", "uniqueItems": True, "items": {"type": "number"}}, [1, 1.0], False),
            ({"type": "object", "additionalProperties": False, "properties": {"a": {"type": "integer"}}}, {"a": 1, "b": 2}, False),
            ({"type": "object", "additionalProperties": {"type": "integer", "minimum": 1}}, {"x": 0}, False),
            ({"type": "string", "minLength": 2}, "é", False),
            ({"type": "integer", "minimum": 1, "maximum": 3}, 4, False),
        ]
        for schema, value, integral_float in cases:
            with self.subTest(schema=schema, value=value):
                self.compare(schema, [(json.dumps(value), value, integral_float)])

    def test_policy_schemas_agree_on_systematic_mutations(self) -> None:
        for filename, schema_name in self.ps.POLICY_SCHEMAS.items():
            schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
            document = _read(filename[:-5])
            cases = _systematic_cases(document)
            with self.subTest(schema=schema_name):
                totals = self.compare(schema, cases)
                self.assertGreater(totals["rejected"], 0)
                self.assertGreater(totals["accepted"], 1)
                self.assertFalse(self.ps.validate_instance(document, schema))


if __name__ == "__main__":
    unittest.main()
