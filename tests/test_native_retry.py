from __future__ import annotations

import copy
import hashlib
import json
import unittest

from scripts.cwo_core.native_retry import (
    RETRY_AUTHORIZATION_TYPE,
    RETRY_AUTHORIZATION_TYPE_V2,
    RETRY_AUTHORIZATION_VERSION,
    RETRY_AUTHORIZATION_VERSION_V1,
    RETRY_AUTHORIZATION_VERSION_V2,
    RETRY_ELIGIBILITY_TYPE,
    RETRY_ELIGIBILITY_VERSION,
    RETRY_ELIGIBLE_NEXT_ACTION,
    RETRY_RECEIPT_AUTHORITY,
    RETRY_REQUIRED_DISPATCH_AUTHORITY,
    build_retry_authorization,
    canonical_work_payload,
    canonical_work_sha256,
    evaluate_retry_eligibility,
    read_retry_authorization,
    validate_retry_authorization,
)
from scripts.cwo_core.native_authority import policy_authority


def _base_packet(packet_id: str = "parent-packet-id") -> dict:
    return {
        "packet_id": packet_id,
        "packet_envelope": {"generated_at": "2026-07-12T00:00:00Z", "tooling": "test"},
        "worker_commitment": {"tool_surface_id": "surface-test"},
        "validation_lineage": ["v1"],
        "telemetry": {"runtime_ms": 500},
        "bead_id": "bead-test-1",
        "lane": "native",
        "requested_model": "qwen2.5-1b",
        "tool_policy": {
            "version": 1,
            "permitted_tools": ["exec_command"],
            "forbidden_tools": ["spawn_agent"],
            "enforcement_mode": "server-allowlist-required",
            "workload_class": "operative",
            "override_provenance": None,
        },
        "scope": {"artifact": "code", "depth": 1},
        "acceptance_checks": ["governance", "quality"],
        "budget": {
            "tool_calls_hard": 3,
            "runtime_seconds_hard": 12,
            "tool_calls_soft": 5,
            "runtime_seconds_soft": 20,
        },
        "return_contract": {"mode": "normal", "target": "artifact"},
        "work_plan": {
            "aggregate_allowance": {"tool_calls_hard": 12, "runtime_seconds_hard": 120},
            "tasks": ["build", "test"],
        },
    }


def _retry_packet(parent_packet: dict, packet_id: str = "retry-packet-id") -> dict:
    packet = copy.deepcopy(parent_packet)
    packet["packet_id"] = packet_id
    packet["packet_envelope"] = {"generated_at": "2026-07-12T00:01:00Z", "tooling": "retry-test"}
    return packet


def _base_state() -> dict:
    return {
        "session_id": "session-parent",
        "decision": "interrupt",
        "reasons": ["delivery-failed"],
        "requested_model": "qwen2.5-1b",
        "control_timing": {"monitor_armed_before_dispatch": True, "late_poll_count": 0},
        "observed": {
            "tool_calls": 1,
            "runtime_seconds": 4,
            "context_compactions": 0,
            "full_suite_runs": 0,
        },
        "recovery": {
            "attempt": 0,
            "cumulative_usage": {"tool_calls": 0, "runtime_seconds": 0},
        },
    }


def _base_workspace() -> dict:
    return {
        "mutation_detected": False,
        "unexpected_mutation_detected": False,
        "attribution_ambiguous": False,
        "incomplete": False,
    }


def _base_semantic(status: str = "delivery-failed") -> dict:
    return {
        "trusted": True,
        "artifact_accepted": False,
        "contradiction": False,
        "status": status,
    }


def _base_policy() -> dict:
    return {
        "enabled": True,
        "max_retries": 1,
        "eligible_semantic_statuses": ["delivery-failed", "no-artifact", "no-progress"],
        "eligible_interrupt_reasons": ["delivery-failed", "no-artifact", "no-progress"],
    }


def _base_attestation() -> dict:
    return {
        "session_id": "session-retry",
        "requested_model": "qwen2.5-1b",
        "attested_model": "qwen2.5-1b",
        "attestation_source": "trusted-session-jsonl",
        "tool_calls": 0,
        "context_compactions": 0,
        "closure_receipt": True,
        "tool_surface_id": "surface-retry",
    }


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()


def _reseal_receipt(receipt: dict) -> dict:
    receipt.pop("receipt_sha256", None)
    receipt["receipt_sha256"] = _canonical_sha256(receipt)
    return receipt


def _reseal_v3_provenance(receipt: dict) -> dict:
    provenance = receipt["evidence_provenance"]
    provenance.pop("provenance_sha256", None)
    provenance["provenance_sha256"] = _canonical_sha256(provenance)
    return _reseal_receipt(receipt)


def _reseal_v2_authority(receipt: dict) -> dict:
    authority = receipt["authority_provenance"]
    authority.pop("authority_sha256", None)
    authority["authority_sha256"] = _canonical_sha256(authority)
    return _reseal_receipt(receipt)


def _current_receipt() -> dict:
    parent = _base_packet()
    return build_retry_authorization(
        parent,
        _retry_packet(parent, "retry-1"),
        _base_state(),
        _base_workspace(),
        _base_semantic(),
        _base_policy(),
        _base_attestation(),
    )


def _historical_v2_receipt(current: dict) -> dict:
    historical = copy.deepcopy(current)
    for field in (
        "schema",
        "evidence_provenance",
        "receipt_authority",
        "dispatch_authorized",
        "required_dispatch_authority",
        "next_action",
        "receipt_sha256",
    ):
        historical.pop(field)
    historical["receipt_type"] = RETRY_AUTHORIZATION_TYPE_V2
    historical["version"] = RETRY_AUTHORIZATION_VERSION_V2
    historical["authority_provenance"] = policy_authority(
        "native-retry-supervisor-policy-v2",
        authorized_scope="execution-path",
        source_sha256=historical["retry_evidence_sha256"],
        identity_source="native-retry-policy",
    ).serialize()
    historical["decision"] = "authorize-one-fresh-retry"
    historical["receipt_sha256"] = _canonical_sha256(historical)
    return historical


def _historical_v1_receipt(v2_receipt: dict) -> dict:
    historical = copy.deepcopy(v2_receipt)
    historical.pop("evidence_bindings")
    historical.pop("retry_evidence_sha256")
    historical.pop("authority_provenance")
    historical.pop("receipt_sha256")
    historical["version"] = RETRY_AUTHORIZATION_VERSION_V1
    historical["authority"] = "cwo-native-supervisor-evidence"
    historical["receipt_sha256"] = _canonical_sha256(historical)
    return historical


class NativeRetryTests(unittest.TestCase):
    def _assert_invalid_receipt(self, receipt: dict, expected_error: str) -> None:
        self.assertIn(expected_error, validate_retry_authorization(receipt))
        with self.assertRaises(ValueError):
            read_retry_authorization(receipt)

    def test_canonical_work_hash_stable_for_metadata_only_changes(self) -> None:
        base = _base_packet()
        variants = [
            ("packet_id", lambda p: p | {"packet_id": "alt-packet-id"}),
            ("packet envelope", lambda p: (p | {"packet_envelope": {"generated_at": "2026-07-12T01:00:00Z"}})),
            ("worker commitment", lambda p: p | {"worker_commitment": {"tool_surface_id": "other"}}),
            ("validation lineage", lambda p: p | {"validation_lineage": ["v2"]}),
            ("telemetry", lambda p: p | {"telemetry": {"runtime_ms": 1234}}),
        ]
        base_hash = canonical_work_sha256(base)
        for label, mutator in variants:
            with self.subTest(label=label):
                packet = mutator(copy.deepcopy(base))
                self.assertEqual(base_hash, canonical_work_sha256(packet))

    def test_canonical_work_hash_changes_for_immutable_work_fields(self) -> None:
        base = _base_packet()
        base_hash = canonical_work_sha256(base)
        checks = {
            "bead_id": ("bead-test-2", "bead_id"),
            "lane": ("native-alt", "lane"),
            "requested_model": ("gpt-4.1", "requested_model"),
            "tool_policy": (
                {
                    "version": 1,
                    "permitted_tools": ["exec_command", "write_stdin"],
                    "forbidden_tools": ["spawn_agent"],
                    "enforcement_mode": "server-allowlist-required",
                    "workload_class": "operative",
                    "override_provenance": None,
                },
                "tool_policy",
            ),
            "scope": ({"artifact": "model", "depth": 2}, "scope"),
            "acceptance_checks": (["quality"], "acceptance_checks"),
            "budget": ({"tool_calls_hard": 4, "runtime_seconds_hard": 14}, "budget"),
            "return_contract": ({"mode": "strict"}, "return_contract"),
            "work_plan": ({"aggregate_allowance": {"tool_calls_hard": 99, "runtime_seconds_hard": 99}}, "work_plan"),
        }
        for label, (value, field) in checks.items():
            with self.subTest(label=label):
                packet = copy.deepcopy(base)
                packet[field] = value
                self.assertNotEqual(base_hash, canonical_work_sha256(packet))

    def test_canonical_work_payload(self) -> None:
        packet = _base_packet()
        payload = canonical_work_payload(packet)
        self.assertEqual(set(payload), {
            "bead_id",
            "lane",
            "requested_model",
            "tool_policy",
            "scope",
            "acceptance_checks",
            "budget",
            "return_contract",
            "work_plan",
        })
        packet["bead_id"] = "changed"
        self.assertNotEqual(payload, canonical_work_payload(packet))

    def _evaluate(self, **kwargs) -> dict:
        packet = _base_packet()
        state = _base_state()
        workspace = _base_workspace()
        semantic = _base_semantic()
        policy = _base_policy()
        packet.update(kwargs.get("packet", {}))
        state.update(kwargs.get("state", {}))
        workspace.update(kwargs.get("workspace", {}))
        semantic.update(kwargs.get("semantic", {}))
        policy.update(kwargs.get("policy", {}))
        return evaluate_retry_eligibility(packet, state, workspace, semantic, policy)

    def test_evaluate_eligibility_success_for_each_permitted_interrupt_reason(self) -> None:
        for reason in ["delivery-failed", "no-artifact", "no-progress"]:
            with self.subTest(reason=reason):
                state = copy.deepcopy(_base_state())
                state["reasons"] = [reason]
                semantic = _base_semantic(status="delivery-failed")
                result = self._evaluate(state=state, semantic=semantic)
                self.assertTrue(result["eligible"])
                self.assertEqual(result["result_type"], RETRY_ELIGIBILITY_TYPE)
                self.assertEqual(result["version"], RETRY_ELIGIBILITY_VERSION)
                self.assertEqual(result["next_attempt"], 1)
                self.assertEqual(result["attempt"], 0)

    def test_eligible_assessment_is_audit_only_and_awaits_verified_action(self) -> None:
        result = self._evaluate()

        self.assertTrue(result["eligible"])
        self.assertEqual(result["receipt_authority"], RETRY_RECEIPT_AUTHORITY)
        self.assertFalse(result["dispatch_authorized"])
        self.assertEqual(
            result["required_dispatch_authority"],
            RETRY_REQUIRED_DISPATCH_AUTHORITY,
        )
        self.assertEqual(result["next_action"], RETRY_ELIGIBLE_NEXT_ACTION)

    def test_evaluate_eligibility_fails_when_allowance_exact_budget_only(self) -> None:
        base = _base_packet()
        state = _base_state()
        state["observed"]["tool_calls"] = 2
        state["observed"]["runtime_seconds"] = 8
        base["budget"]["tool_calls_hard"] = 3
        base["budget"]["runtime_seconds_hard"] = 4
        base["work_plan"]["aggregate_allowance"]["tool_calls_hard"] = 5
        base["work_plan"]["aggregate_allowance"]["runtime_seconds_hard"] = 12
        result = evaluate_retry_eligibility(base, state, _base_workspace(), _base_semantic(), _base_policy())
        self.assertTrue(result["eligible"])

        base["work_plan"]["aggregate_allowance"]["tool_calls_hard"] = 4
        result = evaluate_retry_eligibility(base, state, _base_workspace(), _base_semantic(), _base_policy())
        self.assertFalse(result["eligible"])
        self.assertIn("insufficient-aggregate-retry-budget", result["reasons"])

    def test_evaluate_eligibility_ineligible_conditions(self) -> None:
        cases = [
            ("recovery-disabled", {"policy": {"enabled": False}, "expect": "recovery-disabled"}),
            ("invalid-max-retries", {"policy": {"max_retries": 2}, "expect": "invalid-retry-policy"}),
            ("malformed-eligible-statuses", {"policy": {"eligible_semantic_statuses": [1, 2]}, "expect": "invalid-retry-policy"}),
            ("malformed-eligible-reasons", {"policy": {"eligible_interrupt_reasons": []}, "expect": "ineligible-interrupt-reason"}),
            ("non-interrupt-decision", {"state": {"decision": "pass"}, "expect": "supervisor-not-interrupted"}),
            ("empty-reasons", {"state": {"reasons": []}, "expect": "invalid-supervisor-reasons"}),
            ("mixed-ineligible-reasons", {"state": {"reasons": ["delivery-failed", "bad-reason"]}, "expect": "ineligible-interrupt-reason"}),
            ("model-mismatch", {"state": {"requested_model": "other-model"}, "expect": "model-mismatch"}),
            ("unarmed-control", {"state": {"control_timing": {"monitor_armed_before_dispatch": False, "late_poll_count": 0}}, "expect": "control-loss"}),
            ("late-control", {"state": {"control_timing": {"monitor_armed_before_dispatch": True, "late_poll_count": 2}}, "expect": "control-loss"}),
            ("context-compaction", {"state": {"observed": {"tool_calls": 1, "runtime_seconds": 4, "context_compactions": 1, "full_suite_runs": 0}}, "expect": "context-compaction"}),
            ("full-suite-run", {"state": {"observed": {"tool_calls": 1, "runtime_seconds": 4, "context_compactions": 0, "full_suite_runs": 1}}, "expect": "full-suite-run"},
            ),
            ("mutation-detected", {"workspace": {"mutation_detected": True}, "expect": "workspace-mutation-detected"}),
            ("unexpected-mutation", {"workspace": {"unexpected_mutation_detected": True}, "expect": "workspace-unexpected-mutation-detected"}),
            ("attribution-ambiguous", {"workspace": {"attribution_ambiguous": True}, "expect": "workspace-attribution-ambiguous"}),
            ("incomplete-workspace", {"workspace": {"incomplete": True}, "expect": "workspace-incomplete"}),
            ("missing-workspace-flag", {"workspace": {"incomplete": None}, "expect": "workspace-incomplete"}),
            ("untrusted-semantic", {"semantic": {"trusted": False}, "expect": "untrusted-semantic-evidence"}),
            ("artifact-accepted", {"semantic": {"artifact_accepted": True}, "expect": "artifact-already-accepted"}),
            ("semantic-contradiction", {"semantic": {"contradiction": True}, "expect": "semantic-contradiction"}),
            ("ineligible-status", {"semantic": {"status": "unknown"}, "expect": "ineligible-semantic-status"}),
            ("invalid-recovery-attempt", {"state": {"recovery": {"attempt": -1, "cumulative_usage": {"tool_calls": 0, "runtime_seconds": 0}}}, "expect": "invalid-recovery-attempt"}),
            ("retry-exhausted", {"state": {"recovery": {"attempt": 1, "cumulative_usage": {"tool_calls": 0, "runtime_seconds": 0}}}, "expect": "retry-exhausted"}),
            ("usage-malformed", {"state": {"observed": {"tool_calls": "x", "runtime_seconds": 4, "context_compactions": 0, "full_suite_runs": 0}}, "expect": ValueError}),
            ("budget-malformed", {"packet": {"budget": {"tool_calls_hard": -1, "runtime_seconds_hard": 2}}, "expect": "invalid-retry-budget"},
            ),
            ("aggregate-allowance-exhausted", {"packet": {"work_plan": {"aggregate_allowance": {"tool_calls_hard": -1, "runtime_seconds_hard": 10}}}, "expect": "invalid-aggregate-allowance"},
            ),
        ]
        for label, entry in cases:
            with self.subTest(label=label):
                if entry["expect"] is ValueError:
                    with self.assertRaises(ValueError):
                        self._evaluate(**{k: v for k, v in entry.items() if k in {"packet", "state", "workspace", "semantic", "policy"}})
                    continue
                result = self._evaluate(**{k: v for k, v in entry.items() if k in {"packet", "state", "workspace", "semantic", "policy"}})
                self.assertFalse(result["eligible"])
                self.assertIn(entry["expect"], result["reasons"])

    def test_build_retry_authorization_happy_path(self) -> None:
        parent = _base_packet()
        retry = _retry_packet(parent, "retry-1")
        result = build_retry_authorization(
            parent,
            retry,
            _base_state(),
            _base_workspace(),
            _base_semantic(),
            _base_policy(),
            _base_attestation(),
        )
        self.assertEqual(result["receipt_type"], RETRY_AUTHORIZATION_TYPE)
        self.assertEqual(result["version"], RETRY_AUTHORIZATION_VERSION)
        self.assertEqual(result["schema"], "schemas/native-retry-evidence.schema.json")
        self.assertEqual(result["parent_packet_id"], parent["packet_id"])
        self.assertEqual(result["retry_packet_id"], retry["packet_id"])
        self.assertEqual(result["parent_session_id"], _base_state()["session_id"])
        self.assertEqual(result["retry_session_id"], _base_attestation()["session_id"])
        self.assertEqual(
            result["evidence_provenance"]["provenance_type"],
            "audit-evidence",
        )
        self.assertEqual(
            result["evidence_provenance"]["source_sha256"],
            result["retry_evidence_sha256"],
        )
        self.assertEqual(result["receipt_authority"], "audit-only")
        self.assertFalse(result["dispatch_authorized"])
        self.assertEqual(
            result["required_dispatch_authority"],
            "opaque-verified-recovery-action",
        )
        self.assertEqual(result["next_action"], "await-verified-recovery-action")
        self.assertNotIn("authority_provenance", result)
        self.assertNotIn("decision", result)
        serialized = json.dumps(result, sort_keys=True).lower()
        self.assertNotIn("authorize-one-fresh-retry", serialized)
        self.assertNotIn("spawn-fresh-native-retry", serialized)
        self.assertNotEqual(result["parent_packet_id"], result["retry_packet_id"])
        self.assertEqual(validate_retry_authorization(result), [])
        assessment = evaluate_retry_eligibility(
            parent,
            _base_state(),
            _base_workspace(),
            _base_semantic(),
            _base_policy(),
        )
        self.assertEqual(assessment["receipt_authority"], "audit-only")
        self.assertFalse(assessment["dispatch_authorized"])
        self.assertEqual(
            assessment["next_action"],
            "await-verified-recovery-action",
        )

    def test_build_retry_authorization_rejects_immutable_work_change(self) -> None:
        parent = _base_packet()
        retry = _retry_packet(parent, "retry-1")
        retry["work_plan"]["aggregate_allowance"]["tool_calls_hard"] = 99
        with self.assertRaises(ValueError):
            build_retry_authorization(parent, retry, _base_state(), _base_workspace(), _base_semantic(), _base_policy(), _base_attestation())

    def test_build_retry_authorization_rejects_same_packet_id(self) -> None:
        parent = _base_packet(packet_id="same-id")
        retry = _retry_packet(parent, "same-id")
        with self.assertRaises(ValueError):
            build_retry_authorization(parent, retry, _base_state(), _base_workspace(), _base_semantic(), _base_policy(), _base_attestation())

    def test_build_retry_authorization_rejects_same_session(self) -> None:
        parent = _base_packet()
        retry = _retry_packet(parent, "retry-1")
        attestation = _base_attestation()
        attestation["session_id"] = _base_state()["session_id"]
        with self.assertRaises(ValueError):
            build_retry_authorization(parent, retry, _base_state(), _base_workspace(), _base_semantic(), _base_policy(), attestation)

    def test_build_retry_authorization_rejects_attestation_issues(self) -> None:
        parent = _base_packet()
        retry = _retry_packet(parent, "retry-1")
        attestation = _base_attestation()
        bad_cases = [
            ("untrusted-source", {**attestation, "attestation_source": "untrusted-session-jsonl"}),
            ("tools-used", {**attestation, "tool_calls": 1}),
            ("compactions", {**attestation, "context_compactions": 1}),
            ("no-closure-receipt", {**attestation, "closure_receipt": False}),
            ("model-mismatch", {**attestation, "attested_model": "other-model"}),
            ("missing-field", {k: v for k, v in attestation.items() if k != "tool_surface_id"}),
            ("tool-surfaces", {**attestation, "tool_surface_id": ""}),
            ("session-missing", {**attestation, "session_id": ""}),
        ]
        for label, bad in bad_cases:
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    build_retry_authorization(parent, retry, _base_state(), _base_workspace(), _base_semantic(), _base_policy(), bad)

    def test_validate_retry_authorization_matrix(self) -> None:
        parent = _base_packet()
        retry = _retry_packet(parent, "retry-1")
        authorization = build_retry_authorization(
            parent,
            retry,
            _base_state(),
            _base_workspace(),
            _base_semantic(),
            _base_policy(),
            _base_attestation(),
        )
        self.assertEqual([], validate_retry_authorization(authorization))

        tampered = copy.deepcopy(authorization)
        tampered["next_action"] = "protected-stop"
        self.assertIn("next_action mismatch", validate_retry_authorization(tampered))
        tampered = copy.deepcopy(authorization)
        tampered["dispatch_authorized"] = True
        self.assertIn(
            "dispatch_authorized must be false",
            validate_retry_authorization(tampered),
        )
        tampered = copy.deepcopy(authorization)
        tampered["receipt_sha256"] = "a" * 63 + "b"
        self.assertIn("receipt_sha256 mismatch", validate_retry_authorization(tampered))
        tampered = copy.deepcopy(authorization)
        tampered["attempt_from"] = True
        self.assertIn("retry attempt lineage must be 0 to 1", validate_retry_authorization(tampered))
        tampered = copy.deepcopy(authorization)
        tampered["cumulative_usage"]["tool_calls"] = -1
        self.assertIn("cumulative_usage values must be non-negative integers", validate_retry_authorization(tampered))
        tampered = copy.deepcopy(authorization)
        tampered["evidence_provenance"]["source_id"] = "other-source"
        self.assertTrue(
            any(
                "evidence_provenance" in error
                for error in validate_retry_authorization(tampered)
            )
        )

    def test_validate_and_read_snapshot_hostile_dict_subclass_once(self) -> None:
        receipt = _current_receipt()
        receipt["dispatch_authorized"] = True
        _reseal_receipt(receipt)

        class HostileReceipt(dict):
            def __init__(self, source: dict) -> None:
                super().__init__(source)
                self.get_calls = 0

            def get(self, key: str, default: object = None) -> object:
                self.get_calls += 1
                if key == "dispatch_authorized":
                    return False
                return super().get(key, default)

        hostile = HostileReceipt(receipt)
        self.assertIn(
            "dispatch_authorized must be false",
            validate_retry_authorization(hostile),
        )
        with self.assertRaises(ValueError):
            read_retry_authorization(hostile)
        self.assertEqual(hostile.get_calls, 0)

    def test_v3_top_level_version_requires_exact_integer_type(self) -> None:
        for value in (True, False, 1.0, 2.0, 3.0):
            with self.subTest(value=value):
                receipt = _current_receipt()
                receipt["version"] = value
                _reseal_receipt(receipt)
                self._assert_invalid_receipt(
                    receipt,
                    "version must be an exact integer",
                )

    def test_v3_attempt_lineage_requires_exact_integer_types(self) -> None:
        vectors = (
            ("attempt_from", False),
            ("attempt_from", True),
            ("attempt_from", 0.0),
            ("attempt_from", 1.0),
            ("attempt_to", False),
            ("attempt_to", True),
            ("attempt_to", 1.0),
            ("attempt_to", 2.0),
        )
        for field, value in vectors:
            with self.subTest(field=field, value=value):
                receipt = _current_receipt()
                receipt[field] = value
                _reseal_receipt(receipt)
                self._assert_invalid_receipt(
                    receipt,
                    "retry attempt lineage must be 0 to 1",
                )

    def test_v3_provenance_version_requires_exact_integer_type(self) -> None:
        for value in (True, False, 1.0, 2.0):
            with self.subTest(value=value):
                receipt = _current_receipt()
                receipt["evidence_provenance"]["version"] = value
                _reseal_v3_provenance(receipt)
                self._assert_invalid_receipt(
                    receipt,
                    "evidence_provenance version mismatch",
                )

    def test_v1_historical_integer_fields_require_exact_types(self) -> None:
        baseline = _historical_v1_receipt(
            _historical_v2_receipt(_current_receipt())
        )
        for value in (True, False, 1.0, 2.0):
            with self.subTest(field="version", value=value):
                receipt = copy.deepcopy(baseline)
                receipt["version"] = value
                _reseal_receipt(receipt)
                self._assert_invalid_receipt(
                    receipt,
                    "version must be an exact integer",
                )

        vectors = (
            ("attempt_from", False),
            ("attempt_from", True),
            ("attempt_from", 0.0),
            ("attempt_from", 1.0),
            ("attempt_to", True),
            ("attempt_to", False),
            ("attempt_to", 1.0),
            ("attempt_to", 2.0),
        )
        for field, value in vectors:
            with self.subTest(field=field, value=value):
                receipt = copy.deepcopy(baseline)
                receipt[field] = value
                _reseal_receipt(receipt)
                self._assert_invalid_receipt(
                    receipt,
                    "retry attempt lineage must be 0 to 1",
                )

    def test_v2_historical_integer_fields_require_exact_types(self) -> None:
        baseline = _historical_v2_receipt(_current_receipt())
        for value in (True, False, 1.0, 2.0):
            with self.subTest(field="version", value=value):
                receipt = copy.deepcopy(baseline)
                receipt["version"] = value
                _reseal_receipt(receipt)
                self._assert_invalid_receipt(
                    receipt,
                    "version must be an exact integer",
                )

        vectors = (
            ("attempt_from", False),
            ("attempt_from", True),
            ("attempt_from", 0.0),
            ("attempt_from", 1.0),
            ("attempt_to", True),
            ("attempt_to", False),
            ("attempt_to", 1.0),
            ("attempt_to", 2.0),
        )
        for field, value in vectors:
            with self.subTest(field=field, value=value):
                receipt = copy.deepcopy(baseline)
                receipt[field] = value
                _reseal_receipt(receipt)
                self._assert_invalid_receipt(
                    receipt,
                    "retry attempt lineage must be 0 to 1",
                )

        for value in (True, False, 1.0, 2.0):
            with self.subTest(field="authority_provenance.version", value=value):
                receipt = copy.deepcopy(baseline)
                receipt["authority_provenance"]["version"] = value
                _reseal_v2_authority(receipt)
                self._assert_invalid_receipt(
                    receipt,
                    "authority_provenance version mismatch",
                )

    def test_v2_and_v3_schemas_reject_boolean_integer_aliases(self) -> None:
        try:
            import jsonschema
        except ModuleNotFoundError:
            self.skipTest("jsonschema is not installed")

        with open("schemas/native-retry-evidence.schema.json", encoding="utf-8") as stream:
            v3_schema = json.load(stream)
        with open("schemas/native-retry-authorization.schema.json", encoding="utf-8") as stream:
            v2_schema = json.load(stream)

        v3_cases: list[tuple[str, dict, str]] = []
        for field, value, expected in (
            ("version", True, "version must be an exact integer"),
            ("attempt_from", False, "retry attempt lineage must be 0 to 1"),
            ("attempt_to", True, "retry attempt lineage must be 0 to 1"),
        ):
            receipt = _current_receipt()
            receipt[field] = value
            v3_cases.append((field, _reseal_receipt(receipt), expected))
        receipt = _current_receipt()
        receipt["evidence_provenance"]["version"] = True
        v3_cases.append(
            (
                "evidence_provenance.version",
                _reseal_v3_provenance(receipt),
                "evidence_provenance version mismatch",
            )
        )

        v2_cases: list[tuple[str, dict, str]] = []
        for field, value, expected in (
            ("version", True, "version must be an exact integer"),
            ("attempt_from", False, "retry attempt lineage must be 0 to 1"),
            ("attempt_to", True, "retry attempt lineage must be 0 to 1"),
        ):
            receipt = _historical_v2_receipt(_current_receipt())
            receipt[field] = value
            v2_cases.append((field, _reseal_receipt(receipt), expected))
        receipt = _historical_v2_receipt(_current_receipt())
        receipt["authority_provenance"]["version"] = True
        v2_cases.append(
            (
                "authority_provenance.version",
                _reseal_v2_authority(receipt),
                "authority_provenance version mismatch",
            )
        )

        for schema, cases in ((v3_schema, v3_cases), (v2_schema, v2_cases)):
            for field, receipt, expected in cases:
                with self.subTest(field=field, schema=receipt["version"]):
                    self._assert_invalid_receipt(receipt, expected)
                    with self.assertRaises(jsonschema.ValidationError):
                        jsonschema.validate(receipt, schema)

    def test_v1_and_v2_retry_authorizations_are_historical_read_only(self) -> None:
        current = build_retry_authorization(
            _base_packet(),
            _retry_packet(_base_packet(), "retry-1"),
            _base_state(),
            _base_workspace(),
            _base_semantic(),
            _base_policy(),
            _base_attestation(),
        )
        v2_receipt = _historical_v2_receipt(current)
        self.assertEqual(read_retry_authorization(v2_receipt), v2_receipt)
        self.assertEqual(
            validate_retry_authorization(v2_receipt),
            ["retry authorization version 2 is historical-only"],
        )

        v1_receipt = _historical_v1_receipt(v2_receipt)
        self.assertEqual(read_retry_authorization(v1_receipt), v1_receipt)
        self.assertEqual(
            validate_retry_authorization(v1_receipt),
            ["retry authorization version 1 is historical-only"],
        )

        malformed_v2 = copy.deepcopy(v2_receipt)
        malformed_v2["decision"] = "tampered"
        self.assertIn(
            "decision mismatch",
            validate_retry_authorization(malformed_v2),
        )

    def test_schema_contract(self) -> None:
        with open("schemas/native-retry-evidence.schema.json", encoding="utf-8") as stream:
            schema = json.load(stream)
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(schema.get("additionalProperties", True))
        required = set(schema["required"])
        self.assertEqual(
            required,
            {
                "receipt_type",
                "version",
                "schema",
                "parent_packet_id",
                "retry_packet_id",
                "bead_id",
                "requested_model",
                "attested_model",
                "parent_session_id",
                "retry_session_id",
                "tool_surface_id",
                "attestation_source",
                "work_sha256",
                "attempt_from",
                "attempt_to",
                "cumulative_usage",
                "remaining_before_retry",
                "retry_budget",
                "evidence_bindings",
                "retry_evidence_sha256",
                "evidence_provenance",
                "receipt_authority",
                "dispatch_authorized",
                "required_dispatch_authority",
                "next_action",
                "receipt_sha256",
            },
        )
        self.assertEqual(schema["properties"]["receipt_type"]["const"], RETRY_AUTHORIZATION_TYPE)
        self.assertEqual(schema["properties"]["version"]["const"], RETRY_AUTHORIZATION_VERSION)
        self.assertEqual(
            schema["properties"]["schema"]["const"],
            "schemas/native-retry-evidence.schema.json",
        )
        self.assertEqual(schema["properties"]["attestation_source"]["const"], "trusted-session-jsonl")
        self.assertEqual(schema["properties"]["attempt_from"]["const"], 0)
        self.assertEqual(schema["properties"]["attempt_to"]["const"], 1)
        self.assertEqual(
            schema["properties"]["evidence_provenance"]["$ref"],
            "#/definitions/evidence_provenance",
        )
        self.assertEqual(schema["properties"]["receipt_authority"]["const"], "audit-only")
        self.assertIs(schema["properties"]["dispatch_authorized"]["const"], False)
        self.assertEqual(
            schema["properties"]["required_dispatch_authority"]["const"],
            "opaque-verified-recovery-action",
        )
        self.assertEqual(
            schema["properties"]["next_action"]["const"],
            "await-verified-recovery-action",
        )
        serialized = json.dumps(schema, sort_keys=True).lower()
        self.assertNotIn("authorize-one-fresh-retry", serialized)
        self.assertNotIn("spawn-fresh-native-retry", serialized)
        self.assertEqual(schema["definitions"]["sha256"]["pattern"], "^[0-9a-f]{64}$")
        self.assertEqual(schema["definitions"]["usage"]["additionalProperties"], False)
        self.assertEqual(schema["definitions"]["usage"]["required"], ["tool_calls", "runtime_seconds"])

        with open("schemas/native-retry-authorization.schema.json", encoding="utf-8") as stream:
            historical_v2_schema = json.load(stream)
        self.assertEqual(
            historical_v2_schema["properties"]["receipt_type"]["const"],
            RETRY_AUTHORIZATION_TYPE_V2,
        )
        self.assertEqual(
            historical_v2_schema["properties"]["version"]["const"],
            RETRY_AUTHORIZATION_VERSION_V2,
        )


if __name__ == "__main__":
    unittest.main()
