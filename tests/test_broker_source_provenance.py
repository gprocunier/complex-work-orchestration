"""Offline reliability cases for explicitly versioned broker source fixtures."""

from __future__ import annotations

import ast
import copy
import dataclasses
import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import adjudication_binding as binding
from cwo_core import adjudication_source as source
from cwo_core import policy, policy_schema
from cwo_core.adjudication import dispatch_provenance
from cwo_core.errors import CWOError
from cwo_core.synthesis import evaluate_synthesis_inputs
from tests.test_policy_current_effects import EffectSpies, current_policy


import shutil

def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_policy(name, document):
    path = policy.POLICY_DIR / (name + ".yaml")
    path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    policy.clear_policy_cache()


def original_v1_schema():
    """Read the pinned V1 schema contract without importing archived code."""
    from tests.historical_policy_fixtures import contract_evidence

    try:
        schema = contract_evidence()["provider_v1_schema"]
    except (OSError, ValueError, AssertionError) as exc:
        raise AssertionError("V1 reliability schema fixture is unavailable or drifted") from exc
    return json.dumps(schema, sort_keys=True).encode()


def validation_shape(value):
    if type(value) is dict:
        return {key: validation_shape(item) for key, item in value.items()
                if key not in policy_schema.ANNOTATION_KEYWORDS}
    if type(value) is list:
        return [validation_shape(item) for item in value]
    return value


def install_v2_registry():
    """Write disposable reliability metadata without changing shipped configuration."""
    document = policy.load_policy("provider-registry")
    document["version"] = 2
    template = copy.deepcopy(document["providers"]["human_specialist"])
    for key, family in (
        ("EXAMPLE_DIRECT_A", "example-underlying-a"),
        ("EXAMPLE_DIRECT_B", "example-underlying-b"),
        ("EXAMPLE_BROKER", "example-broker-label")):
        entry = copy.deepcopy(template)
        entry.update(display_name="EXAMPLE reliability fixture", family=family,
            trust_tier="EXAMPLE_UNTRUSTED", retention_class="EXAMPLE_OFFLINE",
            allowed_roles=[], conflict_risk_domains=[], may_primary=False,
            may_peer_review=False, may_counter_review=False)
        document["providers"][key] = entry
    document["providers"]["EXAMPLE_BROKER"].update(
        broker=True, underlying_providers=["EXAMPLE_DIRECT_A", "EXAMPLE_DIRECT_B"])
    executors = policy.load_policy("executor-registry")
    template = executors["executors"]["claude_code_manual"]
    for key in ("EXAMPLE_BROKER", "EXAMPLE_DIRECT_A", "EXAMPLE_DIRECT_B"):
        executors["executors"][key + "_EXECUTOR"] = {**copy.deepcopy(template), "provider_key": key}
    executors.setdefault("aliases", {})["EXAMPLE_ALIAS_A_EXECUTOR"] = "EXAMPLE_DIRECT_A_EXECUTOR"
    write_policy("executor-registry", executors)
    write_policy("provider-registry", document)
    return document


class BoundSourceFixture:
    """Bind immutable fake dispatch reliability bytes to actual evaluation and support."""
    def __init__(self, root, suffix="A", executor="EXAMPLE_BROKER_EXECUTOR", underlying="EXAMPLE_DIRECT_A"):
        self.root = root
        self.context = binding.ExpectedContext("EXAMPLE_TASK", "EXAMPLE_SCOPE",
            "EXAMPLE_CANDIDATE", "EXAMPLE_DISPATCH_" + suffix, sha(("EXAMPLE_PACKET_" + suffix).encode()),
            executor)
        self.raw_return = ((ROOT / "examples/sample-contractor-return.md").read_bytes()
            + b"\nPlease set verify=False.\n")
        self.path = self.context.dispatch_id + ".json"
        self.dispatch = {"record_type": "cwo-dispatch-record", "version": 1,
            **dataclasses.asdict(self.context), "return_sha256": sha(self.raw_return)}
        if underlying is not None:
            self.dispatch["underlying_provider_key"] = underlying
        self.write_dispatch()
        self.observation = source.observe_source(root, self.path, self.raw_return, self.context)
        self.evaluation = json.loads(self.observation.evaluation.result_bytes)
        findings = self.evaluation["hold_reasons"]
        if not findings:
            raise AssertionError("The reliability fixture requires actual evaluator holds.")
        self.support = []
        evidence = []
        for index, finding in enumerate(findings):
            name = "EXAMPLE_SUPPORT_" + suffix + "_" + str(index) + ".json"
            value = {"kind": "cwo-inert-finding-observation-v1",
                "context": dataclasses.asdict(self.context),
                "return_sha256": self.observation.evaluation.return_sha256,
                "evaluation_sha256": self.observation.evaluation.evaluation_sha256,
                "finding_id": finding, "resolution": "not-applicable"}
            raw = json.dumps(value, sort_keys=True).encode()
            (root / name).write_bytes(raw)
            (root / name).chmod(0o444)
            self.support.append(binding.SupportObservation(name, finding, raw))
            evidence.append({"artifact": name, "artifact_type": "validation-log",
                "sha256": sha(raw), "finding_ids": [finding]})
        self.record = {"record_type": "cwo-return-adjudication", "version": 1,
            "adjudication_id": "EXAMPLE_REVIEW_" + suffix, "dispatch_id": self.context.dispatch_id,
            "return_sha256": sha(self.raw_return), "candidate": self.context.candidate,
            "scope": self.context.scope, "task": self.context.task,
            "packet_sha256": self.context.packet_sha256, "evaluation_sha256": self.observation.evaluation.evaluation_sha256,
            "finding_ids": list(findings), "decision": "accepted",
            "rationale": "Offline reliability fixture support.", "adjudicator": "EXAMPLE_REVIEWER",
            "authority": {"rule": "synthesis-input-adjudication"}, "supporting_evidence": evidence}

    def write_dispatch(self, record=None):
        path = self.root / self.path
        if path.exists():
            path.chmod(0o600)
        path.write_bytes(json.dumps(self.dispatch if record is None else record, sort_keys=True).encode())
        path.chmod(0o444)

    def prepare(self, record=None, support=None, expected=None):
        return source.prepare_source(self.observation, expected or self.context,
            self.record if record is None else record, self.root,
            observed_support=tuple(self.support if support is None else support))


def inert_entry(projection):
    """Adapt a consumed reliability decision for the existing offline synthesis consumer."""
    if (projection["source_valid"] is not True or projection["inert_valid"] is not True
            or projection["errors"] or projection["remaining_holds"]
            or projection["decision"] not in ("accepted", "accepted-with-changes")):
        raise AssertionError(
            "A reliability synthesis input requires valid accepting consumption with no errors or holds.")
    context = projection["context"]
    return {**projection["evaluation"], "lane": context["dispatch_id"],
        "dispatch_id": context["dispatch_id"], "return_sha256": projection["return_sha256"],
        "disposition": projection["decision"], "synthesis_use": "primary",
        "hold_reasons": list(projection["remaining_holds"]),
        "implementation_blocked": bool(projection["remaining_holds"]),
        "provider_family": projection["provenance"]["provider_family"]}


class BrokerSourceTests(unittest.TestCase):
    def setUp(self):
        self.home = self.enterContext(current_policy())
        self.addCleanup(policy_schema.clear_schema_cache)
        self.effects = self.enterContext(EffectSpies())
        self.v1 = policy.load_policy("provider-registry")
        self.document = install_v2_registry()
        self.fixture = BoundSourceFixture(self.home)

    def tearDown(self):
        self.assertEqual(self.effects.total(), 0)

    def test_binding_dependency_direction_includes_type_only_imports(self):
        tree = ast.parse((ROOT / "scripts/cwo_core/adjudication_binding.py").read_text(encoding="utf-8"))
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module or "")
                imports.extend(alias.name for alias in node.names)
        self.assertFalse(any(name.split(".")[-1] == "adjudication_source" for name in imports),
            "Binding reliability imports must keep the source layer above binding.")

    def test_binding_owned_dispatch_data_requires_exact_observed_joins(self):
        observed = self.fixture.observation
        dispatch = binding.DispatchObservation(observed.dispatch_path, observed.dispatch_bytes,
            observed.evaluation, observed.provenance_bytes)
        arguments = {"observed_support": tuple(self.fixture.support), "observed_dispatch": dispatch}
        prepared = binding.prepare_adjudication(observed.evaluation, self.fixture.context,
            self.fixture.record, self.home, **arguments)
        self.assertTrue(prepared.inert_valid)
        self.assertEqual(prepared.errors, ())
        self.assertEqual(prepared.remaining_holds, ())
        self.assertEqual(prepared.resolved_findings, tuple(self.fixture.evaluation["hold_reasons"]))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            dispatch.dispatch_bytes = b"EXAMPLE_CHANGED_DISPATCH"
        for field in (*dataclasses.asdict(self.fixture.context), "return_sha256"):
            record = dict(self.fixture.dispatch)
            record[field] = sha(b"EXAMPLE_CHANGED") if field.endswith("sha256") else "EXAMPLE_CHANGED"
            self.fixture.write_dispatch(record)
            changed = dataclasses.replace(dispatch, dispatch_bytes=(self.home / self.fixture.path).read_bytes())
            with self.subTest(field=field):
                prepared = binding.prepare_adjudication(observed.evaluation, self.fixture.context,
                    self.fixture.record, self.home, observed_support=tuple(self.fixture.support),
                    observed_dispatch=changed)
                self.assertFalse(prepared.inert_valid)
                self.assertTrue(prepared.errors)
                self.assertEqual(prepared.resolved_findings, ())
                self.assertEqual(prepared.remaining_holds, tuple(self.fixture.evaluation["hold_reasons"]))
        self.fixture.write_dispatch()

    def assert_exact_refusal(self, receipt, expected, decision):
        result = self.project(self.fixture, receipt, expected)
        self.assert_invalid(result)
        self.assertEqual(result["decision"], decision)
        self.assertEqual(set(result["adjudication_restrictions"]), {decision})

    def test_broker_refusals_survive_missing_dispatch_stale_context_and_policy(self):
        path = self.home / self.fixture.path
        policy_path = policy.POLICY_DIR / "synthesis-policy.yaml"
        original = policy_path.read_bytes()
        for decision in ("rejected", "quarantined"):
            record = copy.deepcopy(self.fixture.record)
            record.update(decision=decision, supporting_evidence=[])
            receipt = self.fixture.prepare(record=record, support=())
            self.assertIs(self.project(self.fixture, receipt)["source_valid"], True)
            path.unlink()
            for failed in (receipt, self.fixture.prepare(record=record, support=())):
                self.assert_exact_refusal(failed, self.fixture.context, decision)
            self.fixture.write_dispatch()
            expected = dataclasses.replace(self.fixture.context, candidate="EXAMPLE_STALE_CANDIDATE")
            for failed in (receipt, self.fixture.prepare(record=record, support=(), expected=expected)):
                self.assert_exact_refusal(failed, expected, decision)
            policy_path.write_bytes(original + b"\n")
            policy.clear_policy_cache()
            try:
                for failed in (receipt, self.fixture.prepare(record=record, support=())):
                    self.assert_exact_refusal(failed, self.fixture.context, decision)
            finally:
                policy_path.write_bytes(original)
                policy.clear_policy_cache()

    def test_stale_broker_source_preserves_refusal_union_without_acceptance(self):
        record = dict(self.fixture.record, decision="rejected", supporting_evidence=[])
        receipt = self.fixture.prepare(record=record, support=())
        changed = dataclasses.replace(receipt.prepared, decision="quarantined",
            adjudication_restrictions=("quarantined",))
        self.fixture.write_dispatch(dict(self.fixture.dispatch, task="EXAMPLE_STALE_TASK"))
        result = self.project(self.fixture, dataclasses.replace(receipt, prepared=changed))
        self.assert_invalid(result)
        self.assertEqual(result["decision"], "rejected")
        self.assertEqual(set(result["adjudication_restrictions"]), {"rejected", "quarantined"})
        for decision in ("EXAMPLE_UNRESOLVED_DECISION", "accepted"):
            record = dict(self.fixture.record, decision=decision)
            result = self.project(self.fixture, self.fixture.prepare(record=record))
            self.assert_invalid(result)
            self.assertIsNone(result["decision"])
            self.assertEqual(set(result["adjudication_restrictions"]), {"rejected", "quarantined"})

    def project(self, fixture, receipt, expected=None):
        projection = source.consume_source(receipt, expected or fixture.context, self.home)
        self.assertIs(projection["production_ready"], False)
        self.assertIs(projection["accepted_for_use"], False)
        self.assertIs(projection["implementation_blocked"], True)
        self.assertIs(projection["trusted_host_authority"], False)
        self.assertEqual(projection["evaluation"], fixture.evaluation)
        return projection

    def synthesize(self, fixtures, projections, labels=None, **overrides):
        self.assertEqual(len(fixtures), len(projections))
        entries = [inert_entry(projection) for projection in projections]
        if labels and entries:
            entries[0].update(labels)
        arguments = {"dispatch_records": [json.loads(fixture.observation.dispatch_bytes) for fixture in fixtures],
            "adjudications": [fixture.record for fixture in fixtures],
            "candidate": fixtures[0].context.candidate, "scope": fixtures[0].context.scope}
        arguments.update(overrides)
        result = evaluate_synthesis_inputs(entries, zero_trust_required=False, **arguments)
        self.assertFalse(result["trusted_host_authority"])
        self.assertFalse(result["zero_trust_consensus"]["required"])
        return result

    def assert_positive(self, fixture, projection, family):
        self.assertIs(projection["source_valid"], True)
        self.assertIs(projection["inert_valid"], True)
        self.assertEqual(projection["errors"], [])
        self.assertEqual(projection["remaining_holds"], [])
        self.assertEqual(projection["decision"], "accepted")
        self.assertEqual(projection["resolved_findings"], fixture.evaluation["hold_reasons"])
        self.assertIs(projection["provenance"]["known"], True)
        self.assertEqual(projection["provenance"]["provider_family"], family)
        self.assertEqual(self.effects.total(), 0)

    def positive_consensus(self, fixtures, projections, families, labels=None):
        self.assertEqual(len(fixtures), len(projections))
        self.assertEqual(len(fixtures), len(families))
        expected = {fixture.context.dispatch_id: family for fixture, family in zip(fixtures, families)}
        self.assertEqual(len(expected), len(fixtures))
        for fixture, projection, family in zip(fixtures, projections, families):
            self.assert_positive(fixture, projection, family)
        result = self.synthesize(fixtures, projections, labels)
        self.assertEqual(result["input_count"], len(fixtures))
        self.assertEqual(result["primary_input_count"], len(fixtures))
        self.assertEqual(result["usable_input_count"], len(fixtures))
        self.assertCountEqual([item["lane"] for item in result["input_summaries"]], expected)
        self.assertCountEqual([item["lane"] for item in result["primary_inputs"]], expected)
        for item in result["primary_inputs"]:
            self.assertEqual(item["synthesis_use"], "primary")
            self.assertIs(item["dispatch_binding"]["provenance_known"], True)
            self.assertEqual(item["dispatch_binding"]["provider_family"], expected[item["lane"]])
        consensus = result["zero_trust_consensus"]
        summaries = consensus["trust_domain_summaries"]
        self.assertEqual(len(summaries), len(fixtures))
        self.assertCountEqual([item["lane"] for item in summaries], expected)
        for item in summaries:
            self.assertIs(item["included_for_independence"], True)
            self.assertEqual(item["synthesis_use"], "primary")
            self.assertEqual(item["trust_domain"], expected[item["lane"]])
        self.assertEqual(consensus["excluded_input_count"], 0)
        self.assertEqual(consensus["excluded_inputs"], [])
        return consensus

    def assert_invalid(self, projection):
        self.assertFalse(projection["source_valid"])
        self.assertFalse(projection["inert_valid"])
        self.assertTrue(projection["errors"])
        self.assertEqual(projection["resolved_findings"], [])
        self.assertEqual(projection["remaining_holds"], self.fixture.evaluation["hold_reasons"])
        self.assertIsNone(projection["provenance"])
        with self.assertRaises(AssertionError):
            inert_entry(projection)

    def assert_document_refused(self, document):
        receipt = self.fixture.prepare()
        write_policy("provider-registry", document)
        with self.assertRaises(policy_schema.PolicySchemaError) as refused:
            policy.load_policy("provider-registry")
        selected = ("provider-registry-v2.schema.json" if
            type(document.get("version")) is int and document["version"] == 2 else "provider-registry.schema.json")
        self.assertIn("schemas/" + selected, str(refused.exception))
        with self.assertRaises(ValueError):
            source.observe_source(self.home, self.fixture.path,
                self.fixture.raw_return, self.fixture.context)
        for invalid in (receipt, self.fixture.prepare()):
            self.assert_invalid(self.project(self.fixture, invalid))
        write_policy("provider-registry", self.document)

    def test_r6_v1_extension_preserves_historical_and_v2_common_contract(self):
        original = original_v1_schema()
        v1 = json.loads(original)
        current = copy.deepcopy(policy_schema.load_policy_schema("provider-registry.schema.json"))
        extension = current["properties"].pop("review_models")
        self.assertEqual(current, v1)
        v2 = copy.deepcopy(policy_schema.load_policy_schema("provider-registry-v2.schema.json"))
        self.assertEqual(v2["properties"].pop("review_models"), extension)
        v2["properties"]["version"]["const"] = 1
        fields = v2["properties"]["providers"]["additionalProperties"]["properties"]
        self.assertEqual(fields.pop("broker"), {"type": "boolean"})
        fields.pop("underlying_providers")
        self.assertEqual(validation_shape(v1), validation_shape(v2))
        write_policy("provider-registry", self.v1)
        self.assertEqual(policy.load_policy("provider-registry"), self.v1)
        v1_broker = copy.deepcopy(self.v1)
        v1_broker["providers"]["human_specialist"].update(broker=True, underlying_providers=["openai_manual"])
        with self.assertRaises(policy_schema.PolicySchemaError) as refused:
            write_policy("provider-registry", v1_broker)
            policy.load_policy("provider-registry")
        self.assertIn(".broker: unexpected field", str(refused.exception))
        self.assertIn("schemas/provider-registry.schema.json", str(refused.exception))

    def test_actual_broker_source_resolves_findings_without_effects(self):
        with mock.patch.object(binding, "observe_evaluation",
                wraps=binding.observe_evaluation) as evaluator:
            observed = source.observe_source(self.home, self.fixture.path,
                self.fixture.raw_return, self.fixture.context)
        evaluator.assert_called_once_with(self.fixture.raw_return, self.fixture.context)
        self.assertIsInstance(observed.dispatch_bytes, bytes)
        self.assertEqual(observed.dispatch_bytes, (self.home / self.fixture.path).read_bytes())
        receipt = source.prepare_source(self.fixture.observation, self.fixture.context,
            self.fixture.record, self.home, observed_support=tuple(self.fixture.support))
        result = self.project(self.fixture, receipt)
        self.assert_positive(self.fixture, result, "example-underlying-a")
        self.assertEqual(result["resolved_findings"], self.fixture.evaluation["hold_reasons"])
        self.assertEqual(result["remaining_holds"], [])
        derived = dispatch_provenance(self.fixture.dispatch)
        self.assertEqual(result["provenance"], derived)
        self.assertEqual(derived["underlying_provider_key"], "EXAMPLE_DIRECT_A")
        self.assertEqual(derived["provider_family"], "example-underlying-a")
        self.assertNotEqual(derived["provider_family"], self.document["providers"]["EXAMPLE_BROKER"]["family"])

    def test_same_underlying_aliases_count_once_and_different_families_count_twice(self):
        broker = self.fixture
        direct = BoundSourceFixture(self.home, "B", "EXAMPLE_DIRECT_A_EXECUTOR", None)
        other = BoundSourceFixture(self.home, "C", "EXAMPLE_DIRECT_B_EXECUTOR", None)
        alias = BoundSourceFixture(self.home, "D", "EXAMPLE_ALIAS_A_EXECUTOR", None)
        projections = [self.project(fixture, fixture.prepare()) for fixture in (broker, direct, alias, other)]
        same = self.positive_consensus([broker, direct, alias], projections[:3],
            ["example-underlying-a"] * 3)
        self.assertEqual(same["independent_trust_domain_count"], 1)
        self.assertEqual(same["independent_trust_domains"], ["example-underlying-a"])
        different = self.positive_consensus([broker, other], [projections[0], projections[3]],
            ["example-underlying-a", "example-underlying-b"])
        self.assertEqual(different["independent_trust_domain_count"], 2)
        self.assertEqual(different["independent_trust_domains"],
            ["example-underlying-a", "example-underlying-b"])
        self.assertEqual(different["consensus_status"], "informational")

    def test_caller_labels_cannot_add_an_independent_family(self):
        projection = self.project(self.fixture, self.fixture.prepare())
        self.assert_positive(self.fixture, projection, "example-underlying-a")
        direct = BoundSourceFixture(self.home, "LABEL_CONTROL", "EXAMPLE_DIRECT_A_EXECUTOR", None)
        control = self.project(direct, direct.prepare())
        self.assert_positive(direct, control, "example-underlying-a")
        for name in ("provider_key", "underlying_provider_key"):
            with self.subTest(field=name):
                consensus = self.positive_consensus([self.fixture, direct], [projection, control],
                    ["example-underlying-a", "example-underlying-a"], {name: "EXAMPLE_DIRECT_B"})
                self.assertEqual(consensus["independent_trust_domain_count"], 1)
                self.assertEqual(consensus["independent_trust_domains"], ["example-underlying-a"])
        for name in ("provider_family", "trust_domain", "provider_camp"):
            for value in ("EXAMPLE_CALLER_FAMILY", None, "", []):
                with self.subTest(field=name, kind=type(value).__name__):
                    result = self.synthesize([self.fixture], [projection], {name: value})
                    consensus = result["zero_trust_consensus"]
                    self.assertEqual(consensus["independent_trust_domain_count"], 0)
                    self.assertEqual(consensus["independent_trust_domains"], [])

    def test_missing_conflicting_and_unbound_dispatch_fields_restore_every_hold(self):
        receipt = self.fixture.prepare()
        cases = []
        for field in (*dataclasses.asdict(self.fixture.context), "return_sha256", "version",
                "record_type", "underlying_provider_key"):
            missing = dict(self.fixture.dispatch)
            missing.pop(field)
            cases.append(missing)
            value = sha(b"EXAMPLE_CHANGED") if field.endswith("sha256") else "EXAMPLE_CHANGED"
            cases.append(dict(self.fixture.dispatch, **{field: value}))
        for field, value in (("provider_key", "EXAMPLE_UNKNOWN"),
                ("provider_key", "EXAMPLE_DIRECT_B"),
                ("underlying_provider_key", None),
                ("underlying_provider_key", "EXAMPLE_UNKNOWN"),
                ("underlying_provider_key", "EXAMPLE_BROKER"),
                ("provider_family", "example-broker-label"),
                ("provider_family", "EXAMPLE_FORGED_FAMILY")):
            cases.append(dict(self.fixture.dispatch, **{field: value}))
        for index, record in enumerate(cases):
            with self.subTest(case=index):
                self.fixture.write_dispatch(record)
                with self.assertRaises((ValueError, CWOError)):
                    source.observe_source(self.home, self.fixture.path,
                        self.fixture.raw_return, self.fixture.context)
                self.assert_invalid(self.project(self.fixture, receipt))
                self.assert_invalid(self.project(self.fixture, self.fixture.prepare()))
        self.fixture.write_dispatch()

    def test_exact_expected_context_and_raw_return_remain_required(self):
        receipt = self.fixture.prepare()
        for field in dataclasses.asdict(self.fixture.context):
            value = sha(b"EXAMPLE_OTHER_PACKET") if field == "packet_sha256" else "EXAMPLE_OTHER"
            expected = dataclasses.replace(self.fixture.context, **{field: value})
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    source.observe_source(self.home, self.fixture.path,
                        self.fixture.raw_return, expected)
                self.assert_invalid(self.project(self.fixture, self.fixture.prepare(expected=expected), expected))
                self.assert_invalid(self.project(self.fixture, receipt, expected))
        with self.assertRaises(ValueError):
            source.observe_source(self.home, self.fixture.path,
                self.fixture.raw_return + b"\nEXAMPLE_CHANGED_RETURN\n", self.fixture.context)

    def test_mutated_observed_dispatch_bytes_cannot_replace_the_runtime_source(self):
        receipt = self.fixture.prepare()
        records = (
            dict(self.fixture.dispatch, underlying_provider_key="EXAMPLE_DIRECT_B"),
            dict(self.fixture.dispatch, provider_key="EXAMPLE_DIRECT_B"),
            dict(self.fixture.dispatch, provider_family="example-underlying-b"),
            dict(self.fixture.dispatch, version=2),
        )
        missing = dict(self.fixture.dispatch)
        missing.pop("underlying_provider_key")
        for index, record in enumerate((*records, missing)):
            raw = json.dumps(record, sort_keys=True).encode()
            observed = dataclasses.replace(self.fixture.observation, dispatch_bytes=raw)
            with self.subTest(case=index):
                changed = dataclasses.replace(receipt, source=observed)
                self.assert_invalid(self.project(self.fixture, changed))
                prepared = source.prepare_source(observed, self.fixture.context, self.fixture.record,
                    self.home, observed_support=tuple(self.fixture.support))
                self.assert_invalid(self.project(self.fixture, prepared))

    def test_runtime_return_and_evaluation_mutations_restore_original_holds(self):
        receipt = self.fixture.prepare()
        observation = receipt.source.evaluation
        changed = json.dumps({**self.fixture.evaluation, "EXAMPLE_RELIABILITY_CHANGE": True}).encode()
        evaluations = (
            dataclasses.replace(observation, raw_return=observation.raw_return + b"\nEXAMPLE_CHANGED_RETURN\n"),
            dataclasses.replace(observation, result_bytes=changed),
            dataclasses.replace(observation, result_bytes=b"{}"),
        )
        for index, evaluation in enumerate(evaluations):
            with self.subTest(case=index):
                observed = dataclasses.replace(receipt.source, evaluation=evaluation)
                self.assert_invalid(self.project(self.fixture, dataclasses.replace(receipt, source=observed)))

    def test_direct_legacy_preparation_keeps_identical_state_and_receipt_bytes(self):
        direct = BoundSourceFixture(self.home, "LEGACY", "EXAMPLE_DIRECT_A_EXECUTOR", None)
        receipt = direct.prepare()
        projection = self.project(direct, receipt)
        self.assert_positive(direct, projection, "example-underlying-a")
        legacy = binding.prepare_adjudication(direct.observation.evaluation, direct.context,
            direct.record, self.home, observed_support=tuple(direct.support))
        explicit = binding.prepare_adjudication(direct.observation.evaluation, direct.context,
            direct.record, self.home, observed_support=tuple(direct.support), observed_dispatch=None)
        self.assertEqual(legacy, explicit)
        self.assertEqual(dataclasses.asdict(legacy), dataclasses.asdict(receipt.prepared))
        self.assertEqual(source._receipt_bytes(direct.observation, legacy), receipt.binding_bytes)
        broker = binding.prepare_adjudication(self.fixture.observation.evaluation, self.fixture.context,
            self.fixture.record, self.home, observed_support=tuple(self.fixture.support))
        self.assertFalse(broker.inert_valid)
        self.assertTrue(broker.errors)
        self.assertEqual(broker.resolved_findings, ())
        self.assertEqual(broker.remaining_holds, tuple(self.fixture.evaluation["hold_reasons"]))

    def test_adjudication_and_support_require_exact_observed_joins(self):
        for field in ("task", "candidate", "scope", "packet_sha256", "dispatch_id",
                "return_sha256", "evaluation_sha256"):
            record = copy.deepcopy(self.fixture.record)
            record[field] = sha(b"EXAMPLE_OTHER") if field.endswith("sha256") else "EXAMPLE_OTHER"
            self.assert_invalid(self.project(self.fixture, self.fixture.prepare(record=record)))
        record = copy.deepcopy(self.fixture.record)
        record["supporting_evidence"] = []
        self.assert_invalid(self.project(self.fixture, self.fixture.prepare(record=record, support=())))
        support = self.fixture.support[0]
        (self.home / support.artifact).chmod(0o600)
        (self.home / support.artifact).write_bytes(support.raw + b"\n")
        self.assert_invalid(self.project(self.fixture, self.fixture.prepare()))

    def test_only_exact_integer_two_selects_v2(self):
        for version in (True, False, 1, 1.0, 2.0, "2", 3, None):
            document = copy.deepcopy(self.document)
            document["version"] = version
            with self.subTest(version=version):
                self.assert_document_refused(document)
        document = copy.deepcopy(self.document)
        document.pop("version")
        self.assert_document_refused(document)

    def test_malformed_and_large_broker_metadata_refuses(self):
        for field, values in (
            ("broker", (1, 0, "true", None, [])),
            ("underlying_providers", (None, True, "EXAMPLE_DIRECT_A", {}, [], [True], [""], ["bad/id"],
                [" EXAMPLE_DIRECT_A"], ["EXAMPLE_DIRECT_A"] * 2,
                ["EXAMPLE_" + str(index) for index in range(33)], ["X" * 129]))):
            for value in values:
                document = copy.deepcopy(self.document)
                document["providers"]["EXAMPLE_BROKER"][field] = value
                with self.subTest(field=field, kind=type(value).__name__):
                    self.assert_document_refused(document)

    def test_unknown_self_broker_cycle_ambiguous_and_direct_declarations_refuse(self):
        for underlying in (None, ["EXAMPLE_UNKNOWN"], ["EXAMPLE_BROKER"]):
            document = copy.deepcopy(self.document)
            broker = document["providers"]["EXAMPLE_BROKER"]
            if underlying is None:
                broker.pop("underlying_providers")
            else:
                broker["underlying_providers"] = underlying
            self.assert_document_refused(document)
        document = copy.deepcopy(self.document)
        other = copy.deepcopy(document["providers"]["EXAMPLE_BROKER"])
        other["underlying_providers"] = ["EXAMPLE_BROKER"]
        document["providers"]["EXAMPLE_OTHER_BROKER"] = other
        document["providers"]["EXAMPLE_BROKER"]["underlying_providers"] = ["EXAMPLE_OTHER_BROKER"]
        self.assert_document_refused(document)
        document = copy.deepcopy(self.document)
        document["providers"]["example_direct_a"] = copy.deepcopy(document["providers"]["EXAMPLE_DIRECT_A"])
        self.assert_document_refused(document)
        for flag in (None, False):
            document = copy.deepcopy(self.document)
            direct = document["providers"]["EXAMPLE_DIRECT_A"]
            direct["underlying_providers"] = ["EXAMPLE_DIRECT_B"]
            if flag is not None:
                direct["broker"] = flag
            self.assert_document_refused(document)

    def test_r6_complete_common_fields_and_closed_metadata_remain_required(self):
        for field in self.v1["providers"]["human_specialist"]:
            document = copy.deepcopy(self.document)
            del document["providers"]["EXAMPLE_BROKER"][field]
            self.assert_document_refused(document)
        for field in json.loads(original_v1_schema())["required"]:
            document = copy.deepcopy(self.document)
            document.pop(field)
            self.assert_document_refused(document)
        document = copy.deepcopy(self.document)
        document["providers"]["EXAMPLE_BROKER"]["schema_path"] = "EXAMPLE_SCHEMA"
        self.assert_document_refused(document)

    def test_upper_bound_and_supported_schema_vocabulary_have_positive_controls(self):
        document = copy.deepcopy(self.document)
        underlying = []
        for index in range(32):
            key = "EXAMPLE_BOUND_" + str(index)
            document["providers"][key] = copy.deepcopy(document["providers"]["EXAMPLE_DIRECT_A"])
            underlying.append(key)
        document["providers"]["EXAMPLE_BROKER"]["underlying_providers"] = underlying
        write_policy("provider-registry", document)
        self.assertEqual(policy.load_policy("provider-registry"), document)
        self.assertEqual(policy_schema.schema_errors(policy_schema.load_policy_schema("provider-registry-v2.schema.json")), [])

    def test_policy_byte_drift_after_observation_restores_every_hold(self):
        receipt = self.fixture.prepare()
        for name in binding.POLICIES:
            path = policy.POLICY_DIR / (name + ".yaml")
            original = path.read_bytes()
            try:
                path.write_bytes(original + b"\n")
                policy.clear_policy_cache()
                with self.subTest(policy=name):
                    self.assert_invalid(self.project(self.fixture, receipt))
                    self.assert_invalid(self.project(self.fixture, self.fixture.prepare()))
            finally:
                path.write_bytes(original)
                policy.clear_policy_cache()

    def test_missing_fixed_history_fails_clearly_without_importing_historical_code(self):
        from tests import historical_policy_fixtures as fixtures

        for failure in (FileNotFoundError("EXAMPLE missing fixture"),
                        AssertionError("EXAMPLE fixture hash drift")):
            with self.subTest(failure=type(failure).__name__), mock.patch.object(
                    fixtures, "contract_evidence", side_effect=failure):
                with self.assertRaisesRegex(AssertionError, "V1 reliability schema fixture is unavailable"):
                    original_v1_schema()

    def test_binding_dispatch_snapshot_rejects_identity_bytes_and_freshness_changes(self):
        observed = self.fixture.observation
        dispatch = binding.DispatchObservation(observed.dispatch_path, observed.dispatch_bytes,
            observed.evaluation, observed.provenance_bytes)
        for changed in (dataclasses.replace(dispatch, evaluation=dataclasses.replace(observed.evaluation)),
                dataclasses.replace(dispatch, dispatch_bytes=bytearray(dispatch.dispatch_bytes)),
                dataclasses.replace(dispatch, provenance_bytes=b"{}"),
                dataclasses.replace(dispatch, dispatch_bytes=dispatch.dispatch_bytes + b"\n"),
                dataclasses.replace(dispatch, dispatch_path="EXAMPLE_MISSING_DISPATCH.json")):
            with self.subTest(kind=type(changed.dispatch_bytes).__name__, path=changed.dispatch_path):
                prepared = binding.prepare_adjudication(observed.evaluation, self.fixture.context,
                    self.fixture.record, self.home, observed_support=tuple(self.fixture.support),
                    observed_dispatch=changed)
                self.assertFalse(prepared.inert_valid)
                self.assertTrue(prepared.errors)
                self.assertEqual(prepared.resolved_findings, ())
                self.assertEqual(prepared.remaining_holds, tuple(self.fixture.evaluation["hold_reasons"]))


    def test_runtime_dispatch_argument_refuses_conversion_and_relabelling(self):
        observed = self.fixture.observation
        copied_evaluation = dataclasses.replace(observed.evaluation)
        relabelled = dict(self.fixture.dispatch, underlying_provider_key="EXAMPLE_DIRECT_B")
        cases = (observed.dispatch_bytes, json.loads(observed.dispatch_bytes),
            dataclasses.asdict(observed),
            dataclasses.replace(observed, evaluation=copied_evaluation),
            dataclasses.replace(observed, provenance_bytes=b"{}"),
            dataclasses.replace(observed, dispatch_bytes=observed.dispatch_bytes + b"\n"),
            dataclasses.replace(observed, dispatch_bytes=bytearray(observed.dispatch_bytes)),
            dataclasses.replace(observed, dispatch_bytes=json.dumps(relabelled).encode()))
        for index, value in enumerate(cases):
            with self.subTest(case=index):
                prepared = binding.prepare_adjudication(observed.evaluation, self.fixture.context,
                    self.fixture.record, self.home, observed_support=tuple(self.fixture.support),
                    observed_dispatch=value)
                self.assertFalse(prepared.inert_valid)
                self.assertTrue(prepared.errors)
                self.assertEqual(prepared.resolved_findings, ())
                self.assertEqual(prepared.remaining_holds, tuple(self.fixture.evaluation["hold_reasons"]))

    def test_positive_synthesis_refuses_an_invalid_direct_lane(self):
        direct = BoundSourceFixture(self.home, "INVALID", "EXAMPLE_DIRECT_A_EXECUTOR", None)
        broker = self.project(self.fixture, self.fixture.prepare())
        self.assert_positive(self.fixture, broker, "example-underlying-a")
        direct.write_dispatch(dict(direct.dispatch, return_sha256=sha(b"EXAMPLE_OTHER_RETURN")))
        invalid = self.project(direct, direct.prepare())
        self.assertIs(invalid["source_valid"], False)
        self.assertIs(invalid["inert_valid"], False)
        self.assertTrue(invalid["errors"])
        with self.assertRaises(AssertionError):
            self.synthesize([self.fixture, direct], [broker, invalid])
        with self.assertRaises(AssertionError):
            self.positive_consensus([self.fixture, direct], [broker, invalid],
                ["example-underlying-a", "example-underlying-a"])

    def test_missing_v2_schema_refuses_with_the_selected_path_and_all_holds(self):
        schema_dir = self.home / "EXAMPLE_SCHEMAS"
        shutil.copytree(ROOT / "schemas", schema_dir)
        (schema_dir / "provider-registry-v2.schema.json").unlink()
        policy_schema.clear_schema_cache()
        policy.clear_policy_cache()
        with mock.patch.object(policy_schema, "SCHEMA_DIR", schema_dir):
            with self.assertRaisesRegex(policy_schema.PolicySchemaError,
                    "schemas/provider-registry-v2.schema.json cannot be read"):
                policy.load_policy("provider-registry")
            self.assert_invalid(self.project(self.fixture, self.fixture.prepare()))
        policy_schema.clear_schema_cache()
        policy.clear_policy_cache()

    def test_existing_consumer_cannot_count_unbound_dispatch_return_or_candidate(self):
        projection = self.project(self.fixture, self.fixture.prepare())
        for overrides in ({"dispatch_records": []}, {"candidate": "EXAMPLE_OTHER_CANDIDATE"},
                {"dispatch_records": [dict(self.fixture.dispatch, return_sha256=sha(b"EXAMPLE_OTHER_RETURN"))]}):
            result = self.synthesize([self.fixture], [projection], **overrides)
            self.assertEqual(result["zero_trust_consensus"]["independent_trust_domain_count"], 0)

if __name__ == "__main__":
    unittest.main()
