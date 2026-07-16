from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_canary_contracts import (  # noqa: E402
    CANARY_AUTHORIZATION_SCHEMA,
    CanaryAuthorizationStore,
    MATERIALIZATION_EVIDENCE_SCHEMA,
    MATERIALIZATION_EVIDENCE_TYPE,
    NativeCanaryContractError,
    consume_steering_receipt,
    new_authorization_state,
    seal_materialization_evidence,
    validate_authorization_state,
    validate_materialization_evidence,
    validate_steering_receipt,
)


def hash_value(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def boundary(label: str, count: int) -> dict:
    return {
        "record_count": count,
        "byte_offset": count * 100,
        "boundary_sha256": hash_value(label),
        "invalid_record_count": 0,
        "trailing_partial": False,
    }


def observation(second: int, label: str = "same") -> dict:
    return {
        "observed_at": f"2026-07-16T00:00:0{second}Z",
        "boundary": boundary(f"boundary-{second}", 4 + second),
        "turn_context_record_index": 2,
        "command_item_index": 0,
        "command_origin": "agent",
        "command_status": "inProgress",
        "terminal_event_count": 0,
        "failed_event_count": 0,
        "declined_event_count": 0,
        "ambiguous_event_count": 0,
    }


def materialization() -> dict:
    session = "session-one"
    turn = "turn-one"
    return seal_materialization_evidence(
        {
            "evidence_type": MATERIALIZATION_EVIDENCE_TYPE,
            "version": 1,
            "schema": MATERIALIZATION_EVIDENCE_SCHEMA,
            "evidence_id": "evidence-one",
            "run_nonce": str(uuid.uuid4()),
            "attempt_nonce": str(uuid.uuid4()),
            "phase_nonce": str(uuid.uuid4()),
            "session_id": session,
            "turn_id": turn,
            "requested_model": "gpt-5.3-codex-spark",
            "attested_model": "gpt-5.3-codex-spark",
            "attested_effort": "low",
            "attestation_source": "initialized-codex-home-session-jsonl-turn-context",
            "command_sha256": hash_value("sleep 20"),
            "baseline": boundary("baseline", 1),
            "liveness_observations": [observation(1), observation(2)],
            "pre_interrupt_observation": observation(3),
            "interrupt": {
                "requested_at": "2026-07-16T00:00:03Z",
                "confirmed_at": "2026-07-16T00:00:04Z",
                "session_id": session,
                "turn_id": turn,
                "outcome": "interrupt-confirmed",
            },
            "terminal": boundary("terminal", 9),
            "status": "interrupt-confirmed",
            "disposition": "accepted",
        }
    )


def steering() -> dict:
    value = {
        "schema": "cwo-steering-receipt:v1",
        "gate": "pre-mutation",
        "bead_id": "complex-work-orchestration-18w.6.1",
        "authorization_id": str(uuid.uuid4()),
        "authorization_sha256": hash_value("authorization"),
        "control_turn_id": "control-one",
        "submission_id": str(uuid.uuid4()),
        "client_user_message_id": str(uuid.uuid4()),
        "session_id": str(uuid.uuid4()),
        "agent": "codex-app-server-native-sol-steering",
        "model": "gpt-5.6-sol",
        "effort": "max",
        "attestation_source": "initialized-codex-home-session-jsonl-turn-context",
        "model_discovery": {
            "id": "gpt-5.6-sol",
            "model": "gpt-5.6-sol",
            "display_name": "GPT-5.6 Sol",
            "default_reasoning_effort": "xhigh",
            "supported_reasoning_efforts_sha256": hash_value("efforts"),
            "model_record_sha256": hash_value("model"),
        },
        "input": {
            "brief_sha256": hash_value("brief"),
            "recovery_plan_sha256": hash_value("plan"),
            "pickup_sha256": hash_value("pickup"),
        },
        "boundary": {
            "baseline": {
                "availability": "not-yet-materialized",
                "record_count": 0,
                "byte_offset": 0,
                "boundary_sha256": hashlib.sha256(b"").hexdigest(),
                "path_sha256": None,
                "invalid_record_count": 0,
                "trailing_partial": False,
            },
            "terminal": {
                "record_count": 20,
                "byte_offset": 2000,
                "boundary_sha256": hash_value("terminal"),
                "path_sha256": hash_value("private-control-path"),
                "invalid_record_count": 0,
                "trailing_partial": False,
            },
        },
        "observed_activity": {
            "function_calls": 0,
            "custom_tool_calls": 0,
            "tool_item_types": [],
            "compactions": 0,
            "workspace_mutations": 0,
        },
        "guard": {
            "before": {"repo_head": "a" * 40, "repo_status_sha256": hash_value("status"), "primary_diff_sha256": hash_value("primary")},
            "after": {"repo_head": "a" * 40, "repo_status_sha256": hash_value("status"), "primary_diff_sha256": hash_value("primary")},
        },
        "opinion": {
            "conditions": ["prove conditions"],
            "confidence": 0.9,
            "findings": [{"severity": "high", "code": "condition", "finding": "prove it"}],
            "recommendation": "conditional-go",
            "steering_summary": "conditional",
        },
        "final_response_sha256": hash_value("final"),
        "started_at": "2026-07-16T00:00:00Z",
        "completed_at": "2026-07-16T00:01:00Z",
        "closure_outcome": "completed-and-archived",
        "disposition": "conditional",
    }
    value["canonical_receipt_sha256"] = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return value


class NativeCanaryContractTests(unittest.TestCase):
    def test_materialization_accepting_happy_path(self) -> None:
        self.assertEqual(validate_materialization_evidence(materialization(), require_accepting=True), [])

    def test_materialization_separation_identity_terminal_and_interrupt_races(self) -> None:
        cases = []
        value = materialization()
        value["liveness_observations"][1]["observed_at"] = "2026-07-16T00:00:01.500Z"
        cases.append((value, "separation"))
        value = materialization()
        value["pre_interrupt_observation"]["turn_context_record_index"] = 3
        cases.append((value, "identity"))
        value = materialization()
        value["liveness_observations"][0]["terminal_event_count"] = 1
        cases.append((value, "terminal"))
        value = materialization()
        value["liveness_observations"][0]["command_status"] = "failed"
        cases.append((value, "command"))
        value = materialization()
        value["interrupt"]["turn_id"] = "other"
        cases.append((value, "interrupt-identity"))
        value = materialization()
        value["interrupt"]["confirmed_at"] = "2026-07-16T00:00:09Z"
        cases.append((value, "deadline"))
        for value, expected in cases:
            value = seal_materialization_evidence(value)
            with self.subTest(expected=expected):
                self.assertTrue(any(expected in error for error in validate_materialization_evidence(value)))

    def test_materialization_privacy_unknown_field_and_hash_tamper(self) -> None:
        value = materialization()
        value["raw_prompt"] = "forbidden"
        errors = validate_materialization_evidence(value)
        self.assertIn("materialization-fields-invalid", errors)
        self.assertTrue(any("privacy-key" in error for error in errors))
        value = materialization()
        value["session_id"] = "changed"
        self.assertIn("materialization-evidence-sha256-mismatch", validate_materialization_evidence(value))

    def test_steering_conditional_requires_bound_go_and_replay_is_rejected(self) -> None:
        receipt = steering()
        self.assertIn("steering-receipt-not-accepting", validate_steering_receipt(receipt, require_accepting=True))
        adjudication = hash_value("adjudication")
        self.assertEqual(
            validate_steering_receipt(
                receipt,
                architect_adjudication_sha256=adjudication,
                architect_decision="go",
                require_accepting=True,
            ),
            [],
        )
        with tempfile.TemporaryDirectory() as temporary:
            registry = Path(temporary) / "consumed.json"
            phase_nonce = str(uuid.uuid4())
            consumption = consume_steering_receipt(
                receipt,
                registry,
                phase_nonce=phase_nonce,
                architect_adjudication_sha256=adjudication,
                architect_decision="go",
            )
            self.assertEqual(len(consumption), 64)
            self.assertEqual(stat.S_IMODE(registry.stat().st_mode), 0o600)
            with self.assertRaisesRegex(NativeCanaryContractError, "replay"):
                consume_steering_receipt(
                    receipt,
                    registry,
                    phase_nonce=str(uuid.uuid4()),
                    architect_adjudication_sha256=adjudication,
                    architect_decision="go",
                )

    def test_steering_model_activity_boundary_and_hash_tamper(self) -> None:
        receipt = steering()
        receipt["model"] = "other"
        self.assertIn("steering-model-effort-mismatch", validate_steering_receipt(receipt))
        receipt = steering()
        receipt["observed_activity"]["function_calls"] = 1
        self.assertIn("steering-nonzero-activity", validate_steering_receipt(receipt))
        receipt = steering()
        receipt["boundary"]["terminal"]["trailing_partial"] = True
        self.assertIn("steering-terminal-boundary-not-clean", validate_steering_receipt(receipt))
        receipt = steering()
        receipt["gate"] = "changed"
        self.assertIn("steering-canonical-sha256-mismatch", validate_steering_receipt(receipt))

    def test_authorization_latch_is_private_monotonic_and_revokes_delayed_actions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "authorization.json"
            store = CanaryAuthorizationStore(path)
            initial = new_authorization_state(
                authorization_id="authorization-one",
                run_nonce=str(uuid.uuid4()),
                now="2026-07-16T00:00:00Z",
            )
            self.assertEqual(validate_authorization_state(initial), [])
            store.initialize(initial)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(store.require_action("tracked-mutation")["state"], "active")
            contained = store.transition(
                "containment-only", reason="protected-fault", now="2026-07-16T00:00:01Z"
            )
            self.assertEqual(contained["sequence"], 1)
            self.assertIn("tracked-mutation", contained["revoked_actions"])
            self.assertEqual(store.require_action("interrupt")["state"], "containment-only")
            for action in ("retry", "relaunch", "tracked-mutation", "release-enable", "push", "install", "publish"):
                with self.subTest(action=action), self.assertRaisesRegex(
                    NativeCanaryContractError, "revoked"
                ):
                    store.require_action(action)
            with self.assertRaisesRegex(NativeCanaryContractError, "transition-forbidden"):
                store.transition("active", reason="late-event", now="2026-07-16T00:00:02Z")
            parked = store.transition("parked", reason="evidence-durable", now="2026-07-16T00:00:03Z")
            self.assertEqual(parked["state"], "parked")

    def test_authorization_complete_is_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = CanaryAuthorizationStore(Path(temporary) / "authorization.json")
            store.initialize(new_authorization_state(authorization_id="a", run_nonce="r", now="2026-07-16T00:00:00Z"))
            completed = store.transition("complete", reason="accepted", now="2026-07-16T00:00:01Z")
            self.assertEqual(completed["allowed_actions"], [])
            with self.assertRaisesRegex(NativeCanaryContractError, "transition-forbidden"):
                store.transition("containment-only", reason="late", now="2026-07-16T00:00:02Z")

    def test_schemas_are_json_and_strict(self) -> None:
        for relative in (
            "schemas/native-steering-receipt.schema.json",
            MATERIALIZATION_EVIDENCE_SCHEMA,
            CANARY_AUTHORIZATION_SCHEMA,
        ):
            value = json.loads((ROOT / relative).read_text(encoding="utf-8"))
            self.assertFalse(value["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
