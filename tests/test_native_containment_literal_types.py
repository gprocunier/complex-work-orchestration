"""Typed containment metadata at direct, canonical and refusal boundaries."""

from __future__ import annotations

import json
import sys
import unittest
from collections import UserDict
from copy import deepcopy
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import native_containment as nc, policy, policy_schema as ps, routing  # noqa: E402
from tests.historical_policy_fixtures import historical_v2_policy  # noqa: E402
from tests.test_policy_schema import malformed_policy  # noqa: E402


LITERAL_CASES = (
    ("version", 2.0, True),
    ("version", True, True),
    ("version", "2", True),
    ("active", 1, True),
    ("active", 1.0, True),
    ("active", "true", True),
    ("active", False, False),
    ("operative_dispatch_authorized", 1, True),
    ("operative_dispatch_authorized", 1.0, True),
    ("operative_dispatch_authorized", "true", True),
    ("operative_dispatch_authorized", False, False),
)
STRING_FIELDS = (
    "status",
    "scope",
    "reason",
    "decision",
    "authority",
    "release_requires",
    "maximum_release_state",
)


class _LiteralText(str):
    pass


class NativeContainmentLiteralTypesTests(unittest.TestCase):
    def setUp(self) -> None:
        policy.clear_policy_cache()
        self.addCleanup(policy.clear_policy_cache)

    def assert_policy_refused(self, source, fragment) -> None:
        with self.assertRaises(ValueError) as raised:
            nc.native_operative_containment(source)
        self.assertIn("malformed policy: precommit_containment", str(raised.exception))
        self.assertIn(fragment, str(raised.exception))
        with mock.patch.object(
            nc, "validate_native_release_evidence", side_effect=AssertionError("malformed policy reached evidence validation"),
        ) as validator:
            evidence = {"release_state": "operative-authorized"}
            error = nc.containment_error("native-dispatch", source, release_evidence=evidence)
            self.assertTrue(error.startswith(
                f"{nc.CONTAINMENT_ERROR}: containment policy unavailable or invalid:"
            ))
            self.assertIn(fragment, error)
            with self.assertRaises(SystemExit) as stopped:
                nc.require_native_operative_dispatch(
                    "native-dispatch", source, release_evidence=evidence,
                )
            self.assertEqual(str(stopped.exception), error)
        validator.assert_not_called()

    def assert_canonical_routing_refused(self, fragment) -> None:
        with mock.patch.object(routing, "load_policy") as downstream, \
                mock.patch.object(routing, "resolve_operative_route") as fallback:
            with self.assertRaises(ValueError) as raised:
                routing.classify_work("Fix the typo in README")
        self.assertIn("malformed policy: precommit_containment", str(raised.exception))
        self.assertIn(fragment, str(raised.exception))
        downstream.assert_not_called()
        fallback.assert_not_called()

    def assert_canonical_schema_refused(self, field) -> None:
        with self.assertRaises(ps.PolicySchemaError) as raised:
            nc.native_operative_containment()
        message = str(raised.exception)
        self.assertIn("policy/native-worker-execution.yaml does not match schemas/native-worker-execution-policy.schema.json", message)
        self.assertIn(f"$.precommit_containment.{field}", message)
        self.assertNotIn("malformed policy: precommit_containment", message)
        with mock.patch.object(nc, "validate_native_release_evidence") as validator, \
                mock.patch.object(routing, "load_policy") as downstream, \
                mock.patch.object(routing, "resolve_operative_route") as fallback:
            evidence = {"release_state": "operative-authorized"}
            error = nc.containment_error("native-dispatch", release_evidence=evidence)
            self.assertEqual(error, f"{nc.CONTAINMENT_ERROR}: containment policy unavailable or invalid: {message}")
            with self.assertRaises(SystemExit) as stopped:
                nc.require_native_operative_dispatch("native-dispatch", release_evidence=evidence)
            self.assertEqual(str(stopped.exception), error)
            with self.assertRaises(ps.PolicySchemaError) as stopped:
                routing.classify_work("Fix the typo in README")
            self.assertEqual(str(stopped.exception), message)
        validator.assert_not_called()
        downstream.assert_not_called()
        fallback.assert_not_called()

    def assert_bad_document(self, document, fragment, *, schema_field=None) -> None:
        source = UserDict(deepcopy(document))
        if "precommit_containment" in source:
            source["precommit_containment"] = UserDict(source["precommit_containment"])
        self.assert_policy_refused(source, fragment)
        with malformed_policy("native-worker-execution", raw=json.dumps(document)):
            if schema_field is not None:
                self.assert_canonical_schema_refused(schema_field)
            else:
                self.assert_policy_refused(None, fragment)
                self.assert_canonical_routing_refused(fragment)

    def test_numeric_boolean_and_wrong_string_literals_are_refused(self) -> None:
        for field, replacement, schema_error in LITERAL_CASES:
            with self.subTest(field=field, value=replacement, value_type=type(replacement).__name__):
                document = policy.load_policy("native-worker-execution")
                document["precommit_containment"][field] = replacement
                self.assert_bad_document(
                    document, field, schema_field=field if schema_error else None,
                )

    def test_wrong_string_constants_are_refused(self) -> None:
        for field in STRING_FIELDS:
            with self.subTest(field=field):
                document = policy.load_policy("native-worker-execution")
                document["precommit_containment"][field] += "-changed"
                self.assert_bad_document(document, field)

    def test_missing_and_unknown_fields_remain_refused(self) -> None:
        original = policy.load_policy("native-worker-execution")
        for field in original["precommit_containment"]:
            with self.subTest(missing=field):
                document = deepcopy(original)
                del document["precommit_containment"][field]
                self.assert_bad_document(document, "missing " + field)
        unknown = deepcopy(original)
        unknown["precommit_containment"]["unknown"] = True
        self.assert_bad_document(unknown, "unknown unknown", schema_field="unknown")
        missing_section = deepcopy(original)
        del missing_section["precommit_containment"]
        self.assert_bad_document(missing_section, "must be an object")
        self.assert_policy_refused({}, "must be an object")

    def assert_valid_state(self, source) -> dict:
        state = nc.native_operative_containment(source)
        self.assertIs(type(state["version"]), int)
        self.assertEqual(state["version"], 2)
        self.assertIs(state["active"], True)
        self.assertIs(state["operative_dispatch_authorized"], True)
        self.assertIs(state["canary_authorized"], True)
        self.assertIs(state["dispatch_authorized"], True)
        self.assertIs(state["evidence_required"], True)
        self.assertEqual(state["release_state_order"], list(nc.RELEASE_STATES))
        error = nc.containment_error("native-dispatch", source)
        self.assertEqual(
            error,
            f"{nc.CONTAINMENT_ERROR}: native-dispatch is blocked by {nc.CONTAINMENT_REASON} "
            f"until {nc.CONTAINMENT_RELEASE}",
        )
        with self.assertRaises(SystemExit) as stopped:
            nc.require_native_operative_dispatch("native-dispatch", source)
        self.assertEqual(str(stopped.exception), error)
        return state

    def test_current_policy_is_valid_and_returns_independent_state(self) -> None:
        document = policy.load_policy("native-worker-execution")
        before = deepcopy(document)
        state = self.assert_valid_state(UserDict(document))
        self.assert_valid_state(None)
        self.assertEqual(document, before)
        for field in ("allowed_non_operative_operations", "blocked_operations", "release_state_order", "canary_operations"):
            self.assertIsNot(state[field], document["precommit_containment"][field])
        state["blocked_operations"].append("test-only-mutation")
        self.assertEqual(document, before)
        self.assertEqual(policy.load_policy("native-worker-execution"), before)

    @historical_v2_policy()
    def test_accepted_historical_fixture_remains_valid_without_dispatch_evidence(self) -> None:
        self.assert_valid_state(None)
        self.assert_valid_state(UserDict(policy.load_policy("native-worker-execution")))

    def test_string_subclasses_keep_existing_literal_equality(self) -> None:
        document = policy.load_policy("native-worker-execution")
        document["precommit_containment"]["status"] = _LiteralText("operative-authorized")
        self.assert_valid_state(UserDict(document))

    def test_mocked_evidence_positive_is_only_a_wrapper_control(self) -> None:
        # An incomplete test mapping has no real release authority.
        evidence = {"release_state": "operative-authorized"}
        for source in (policy.load_policy("native-worker-execution"), None):
            with self.subTest(explicit_policy=source is not None):
                with mock.patch.object(nc, "validate_native_release_evidence", return_value=[]) as validator:
                    self.assertEqual(nc.containment_error("native-dispatch", source, release_evidence=evidence), "")
                    self.assertIsNone(nc.require_native_operative_dispatch(
                        "native-dispatch", source, release_evidence=evidence,
                    ))
                self.assertEqual(validator.call_count, 2)
                for call in validator.call_args_list:
                    self.assertIs(call.args[0], evidence)
                    self.assertIs(call.kwargs["policy"], source)
                    self.assertEqual(call.kwargs["operation"], "native-dispatch")

    def test_evidence_rejection_remains_a_wrapper_refusal(self) -> None:
        with mock.patch.object(nc, "validate_native_release_evidence", return_value=["test-only rejection"]):
            error = nc.containment_error("native-dispatch", release_evidence={})
            self.assertEqual(error, f"{nc.CONTAINMENT_ERROR}: release evidence rejected: test-only rejection")
            with self.assertRaises(SystemExit) as stopped:
                nc.require_native_operative_dispatch("native-dispatch", release_evidence={})
            self.assertEqual(str(stopped.exception), error)


if __name__ == "__main__":
    unittest.main()
