from __future__ import annotations

import copy
import json
import unittest

from scripts.cwo_core.native_retry import (
    RETRY_AUTHORIZATION_TYPE,
    RETRY_AUTHORIZATION_VERSION,
    RETRY_ELIGIBILITY_TYPE,
    build_retry_authorization,
    canonical_work_payload,
    canonical_work_sha256,
    evaluate_retry_eligibility,
    validate_retry_authorization,
)


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


class NativeRetryTests(unittest.TestCase):
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
                self.assertEqual(result["version"], RETRY_AUTHORIZATION_VERSION)
                self.assertEqual(result["next_attempt"], 1)
                self.assertEqual(result["attempt"], 0)

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
        self.assertEqual(result["parent_packet_id"], parent["packet_id"])
        self.assertEqual(result["retry_packet_id"], retry["packet_id"])
        self.assertEqual(result["parent_session_id"], _base_state()["session_id"])
        self.assertEqual(result["retry_session_id"], _base_attestation()["session_id"])
        self.assertEqual(result["authority"], "cwo-native-supervisor-evidence")
        self.assertNotEqual(result["parent_packet_id"], result["retry_packet_id"])
        self.assertEqual(validate_retry_authorization(result), [])

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
        tampered["decision"] = "deny"
        self.assertIn("decision mismatch", validate_retry_authorization(tampered))
        tampered = copy.deepcopy(authorization)
        tampered["receipt_sha256"] = "a" * 63 + "b"
        self.assertIn("receipt_sha256 mismatch", validate_retry_authorization(tampered))
        tampered = copy.deepcopy(authorization)
        tampered["attempt_from"] = True
        self.assertIn("retry attempt lineage must be 0 to 1", validate_retry_authorization(tampered))
        tampered = copy.deepcopy(authorization)
        tampered["cumulative_usage"]["tool_calls"] = -1
        self.assertIn("cumulative_usage values must be non-negative integers", validate_retry_authorization(tampered))

    def test_schema_contract(self) -> None:
        with open("schemas/native-retry-authorization.schema.json", encoding="utf-8") as stream:
            schema = json.load(stream)
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(schema.get("additionalProperties", True))
        required = set(schema["required"])
        self.assertEqual(
            required,
            {
                "receipt_type",
                "version",
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
                "authority",
                "decision",
                "receipt_sha256",
            },
        )
        self.assertEqual(schema["properties"]["receipt_type"]["const"], RETRY_AUTHORIZATION_TYPE)
        self.assertEqual(schema["properties"]["version"]["const"], RETRY_AUTHORIZATION_VERSION)
        self.assertEqual(schema["properties"]["attestation_source"]["const"], "trusted-session-jsonl")
        self.assertEqual(schema["properties"]["attempt_from"]["const"], 0)
        self.assertEqual(schema["properties"]["attempt_to"]["const"], 1)
        self.assertEqual(schema["properties"]["authority"]["const"], "cwo-native-supervisor-evidence")
        self.assertEqual(schema["properties"]["decision"]["const"], "authorize-one-fresh-retry")
        self.assertEqual(schema["definitions"]["sha256"]["pattern"], "^[0-9a-f]{64}$")
        self.assertEqual(schema["definitions"]["usage"]["additionalProperties"], False)
        self.assertEqual(schema["definitions"]["usage"]["required"], ["tool_calls", "runtime_seconds"])


if __name__ == "__main__":
    unittest.main()
