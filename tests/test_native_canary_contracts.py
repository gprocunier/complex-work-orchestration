from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import importlib.util
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
    length_framed_sha256,
    materialization_execution_correlation,
    new_authorization_state,
    neutral_steering_final_text,
    operator_fact_action_sha256,
    seal_neutral_steering_receipt,
    seal_materialization_evidence,
    validate_capability_rendered_command,
    validate_authorization_state,
    validate_materialization_evidence,
    validate_steering_receipt,
    verify_operator_fact_authority,
    steering_stop_metadata,
)


def hash_value(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


CANONICAL_UUID_TEXT = "123e4567-e89b-12d3-a456-426614174000"
UUID_TEXT_ALIASES = (
    CANONICAL_UUID_TEXT.upper(),
    "{" + CANONICAL_UUID_TEXT + "}",
    uuid.UUID(CANONICAL_UUID_TEXT).hex,
    "urn:uuid:" + CANONICAL_UUID_TEXT,
    " " + CANONICAL_UUID_TEXT,
    CANONICAL_UUID_TEXT + " ",
    CANONICAL_UUID_TEXT + "\n",
)
OPERATOR_FACT_STATEMENT = "The operator bounded this work to the current task."


def boundary(label: str, count: int) -> dict:
    return {
        "record_count": count,
        "byte_offset": count * 100,
        "boundary_sha256": hash_value(label),
        "invalid_record_count": 0,
        "trailing_partial": False,
    }


def observation(
    second: int,
    label: str = "same",
    *,
    session: str = "session-one",
    thread: str = "session-one",
    turn: str = "turn-one",
) -> dict:
    command_item = hash_value("item")
    function_call = hash_value("call")
    rendered = validate_capability_rendered_command(
        "/bin/bash -lc 'sleep 20'", raw_command="sleep 20"
    )
    correlation = materialization_execution_correlation(
        connection_epoch_sha256=hash_value("connection"),
        session_id=session,
        thread_id=thread,
        turn_id=turn,
        command_item_id_sha256=command_item,
        function_call_id_sha256=function_call,
        notification_sequence=4,
        notification_received_monotonic_ns=100,
        notification_started_at_ms=42,
        turn_context_record_index=2,
        function_call_record_index=3,
        rendered_command_sha256=rendered,
        raw_command_sha256=hash_value("sleep 20"),
    )
    return {
        "observed_at": f"2026-07-16T00:00:0{second}Z",
        "boundary": boundary(f"boundary-{second}", 4 + second),
        "session_source_identity_sha256": hash_value("source"),
        "connection_epoch_sha256": hash_value("connection"),
        "notification_sequence": 4,
        "notification_received_monotonic_ns": 100,
        "notification_started_at_ms": 42,
        "turn_context_record_index": 2,
        "function_call_record_index": 3,
        "command_item_id_sha256": command_item,
        "function_call_id_sha256": function_call,
        "rendered_command_sha256": rendered,
        "execution_correlation_sha256": correlation,
        "notification_command_semantic_match": True,
        "notification_workspace_match": True,
        "command_source": "unifiedExecStartup",
        "command_status": "inProgress",
        "started_event_count": 1,
        "function_call_count": 1,
        "completed_event_count": 0,
        "paired_result_count": 0,
        "competing_call_count": 0,
        "terminal_event_count": 0,
        "failed_event_count": 0,
        "declined_event_count": 0,
        "ambiguous_event_count": 0,
    }


def control_observations() -> list[dict]:
    boundaries = [
        boundary("boundary-1", 5),
        boundary("boundary-2", 6),
        boundary("boundary-3", 7),
        boundary("interrupt", 8),
        boundary("terminal", 9),
    ]
    phases = [
        "materialization",
        "materialization",
        "pre-interrupt",
        "interrupt-confirmation",
        "terminal",
    ]
    decisions = [
        "ready",
        "ready",
        "ready",
        "interrupt-confirmed",
        "terminal-accepted",
    ]
    values = []
    previous = boundary("baseline", 1)
    for ordinal, (current, phase, decision) in enumerate(
        zip(boundaries, phases, decisions)
    ):
        interrupted = phase in {"interrupt-confirmation", "terminal"}
        values.append(
            {
                "ordinal": ordinal,
                "elapsed_monotonic_ms": ordinal * 250.0,
                "phase": phase,
                "projected_status": "interrupted" if interrupted else "active",
                "durable_status": "interrupted" if interrupted else None,
                "source_identity_sha256": hash_value("source"),
                "previous_boundary_sha256": previous["boundary_sha256"],
                "boundary": current,
                "decision": decision,
            }
        )
        previous = current
    return values


def materialization() -> dict:
    session = "session-one"
    turn = "turn-one"
    return seal_materialization_evidence(
        {
            "evidence_type": MATERIALIZATION_EVIDENCE_TYPE,
            "version": 4,
            "schema": MATERIALIZATION_EVIDENCE_SCHEMA,
            "evidence_id": "evidence-one",
            "run_nonce": str(uuid.uuid4()),
            "attempt_nonce": str(uuid.uuid4()),
            "phase_nonce": str(uuid.uuid4()),
            "session_id": session,
            "thread_id": session,
            "turn_id": turn,
            "requested_model": "gpt-5.3-codex-spark",
            "attested_model": "gpt-5.3-codex-spark",
            "attested_effort": "low",
            "attestation_source": "initialized-codex-home-session-jsonl-and-local-app-server-stdio-notifications",
            "connection_epoch_sha256": hash_value("connection"),
            "command_sha256": hash_value("sleep 20"),
            "session_source_identity_sha256": hash_value("source"),
            "baseline": boundary("baseline", 1),
            "control_observations": control_observations(),
            "liveness_observations": [observation(1), observation(2)],
            "pre_interrupt_observation": observation(3),
            "interrupt": {
                "requested_at": "2026-07-16T00:00:03Z",
                "request_accepted_at": "2026-07-16T00:00:03.100Z",
                "confirmed_at": "2026-07-16T00:00:04Z",
                "session_id": session,
                "thread_id": session,
                "turn_id": turn,
                "request_outcome": "accepted",
                "outcome": "interrupt-confirmed",
            },
            "terminal": boundary("terminal", 9),
            "terminal_event": {
                "record_index": 8,
                "event_type": "turn_aborted",
                "status": "interrupted",
                "count": 1,
            },
            "status": "interrupt-confirmed",
            "disposition": "accepted",
        }
    )


def steering() -> dict:
    value = {
        "schema": "cwo-steering-receipt:v2",
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
            "before": {
                "repo_head": "a" * 40,
                "repo_status_sha256": hash_value("status"),
                "primary_diff_sha256": hash_value("primary"),
            },
            "after": {
                "repo_head": "a" * 40,
                "repo_status_sha256": hash_value("status"),
                "primary_diff_sha256": hash_value("primary"),
            },
        },
        "steering": {
            "operator_facts": [],
            "observed_evidence": [
                {
                    "severity": "high",
                    "code": "condition",
                    "observation": "prove it",
                    "evidence_sha256": hash_value("condition-evidence"),
                }
            ],
            "model_interpretation": "The evidence leaves one material condition.",
            "recommendation": {
                "outcome": "conditional-go",
                "rationale": "Proceed only after the condition is adjudicated.",
                "confidence": 0.9,
                "confidence_role": "advisory-only",
            },
            "strongest_counterargument": "The condition may warrant a stop.",
            "agent_authored_constraints": [
                {
                    "constraint": "prove conditions",
                    "origin": "agent-authored",
                    "authority": "advisory-only",
                }
            ],
        },
        "started_at": "2026-07-16T00:00:00Z",
        "completed_at": "2026-07-16T00:01:00Z",
        "closure_outcome": "completed-and-archived",
        "disposition": "conditional",
    }
    return seal_neutral_steering_receipt(value)


def stop_steering_receipt() -> dict:
    receipt = steering()
    receipt["steering"]["recommendation"]["outcome"] = "stop"
    receipt["steering"]["observed_evidence"] = [
        {
            "severity": "high",
            "code": "A-1",
            "observation": "fix this",
            "evidence_sha256": hash_value("A-1"),
        },
        {
            "severity": "medium",
            "code": "B-2",
            "observation": "patch this",
            "evidence_sha256": hash_value("B-2"),
        },
        {
            "severity": "low",
            "code": "L-9",
            "observation": "non-blocking",
            "evidence_sha256": hash_value("L-9"),
        },
    ]
    receipt["disposition"] = "rejected"
    return seal_neutral_steering_receipt(receipt)


def historical_steering_receipt() -> dict:
    current = steering()
    payload = current.pop("steering")
    for field in ("stop_scope", "authorized_continuation_paths", "scope_authority"):
        current.pop(field)
    current["schema"] = "cwo-steering-receipt:v1"
    current["opinion"] = {
        "conditions": [
            item["constraint"] for item in payload["agent_authored_constraints"]
        ],
        "confidence": payload["recommendation"]["confidence"],
        "findings": [
            {
                "severity": item["severity"],
                "code": item["code"],
                "finding": item["observation"],
            }
            for item in payload["observed_evidence"]
            if item["severity"] != "info"
        ],
        "recommendation": payload["recommendation"]["outcome"],
        "steering_summary": payload["model_interpretation"],
    }
    current["final_response_sha256"] = hashlib.sha256(
        json.dumps(current["opinion"], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    current.pop("canonical_receipt_sha256", None)
    current["canonical_receipt_sha256"] = hashlib.sha256(
        json.dumps(current, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return current


def verified_operator_authority(
    statement: str = OPERATOR_FACT_STATEMENT,
):
    verification_key = b"test-steering-operator-key"
    action_sha256 = operator_fact_action_sha256(statement)
    body = {
        "version": 1,
        "directive_id": "operator-directive-steering-fact",
        "action_sha256": action_sha256,
        "actor_id": "operator-one",
        "identity_source": "test-operator-keyring",
        "authorized_scope": "complete-task",
        "parent_receipt_sha256": None,
        "issued_at": "2026-07-16T00:00:00Z",
        "nonce": "operator-steering-fact-nonce",
    }
    signature = hmac.new(
        verification_key,
        json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode(),
        hashlib.sha256,
    ).hexdigest()
    return verify_operator_fact_authority(
        statement,
        {**body, "signature": signature},
        verification_key=verification_key,
        expected_actor_id="operator-one",
        expected_identity_source="test-operator-keyring",
    )


def resolved_stop_adjudication(receipt: dict) -> dict:
    return {
        "schema": "cwo-resolved-stop-adjudication:v1",
        "gate": "pre-mutation",
        "steering_receipt_canonical_sha256": receipt["canonical_receipt_sha256"],
        "resolved_findings": [
            {"code": "A-1", "severity": "high", "status": "resolved"},
            {"code": "B-2", "severity": "medium", "status": "resolved"},
        ],
        "unresolved_high_severity_findings": [],
        "post_resolution_commit": "d" * 40,
        "resolution_evidence_sha256": "e" * 64,
        "pre_live_reconfirmation_required": True,
    }


class NativeCanaryContractTests(unittest.TestCase):
    def test_runtime_uuid_identities_reject_textual_aliases(self) -> None:
        for alias in UUID_TEXT_ALIASES:
            with self.subTest(surface="materialization", alias=repr(alias)):
                evidence = materialization()
                evidence["run_nonce"] = alias
                evidence = seal_materialization_evidence(evidence)
                self.assertIn(
                    "materialization-run_nonce-not-uuid",
                    validate_materialization_evidence(evidence),
                )
            for field in (
                "authorization_id",
                "submission_id",
                "client_user_message_id",
                "session_id",
            ):
                with self.subTest(surface="steering", field=field, alias=repr(alias)):
                    receipt = steering()
                    receipt[field] = alias
                    receipt.pop("canonical_receipt_sha256", None)
                    receipt["canonical_receipt_sha256"] = hashlib.sha256(
                        json.dumps(
                            receipt, sort_keys=True, separators=(",", ":")
                        ).encode()
                    ).hexdigest()
                    self.assertIn(
                        f"steering-{field}-not-canonical-uuid",
                        validate_steering_receipt(receipt),
                    )
            with self.subTest(surface="phase-nonce", alias=repr(alias)):
                receipt = steering()
                adjudication = hash_value("adjudication")
                with (
                    tempfile.TemporaryDirectory() as temporary,
                    self.assertRaisesRegex(
                        NativeCanaryContractError, "phase-nonce-invalid"
                    ),
                ):
                    consume_steering_receipt(
                        receipt,
                        Path(temporary) / "registry.json",
                        phase_nonce=alias,
                        architect_adjudication_sha256=adjudication,
                        architect_decision="go",
                    )
            with self.subTest(surface="authorization-v2", alias=repr(alias)):
                with self.assertRaisesRegex(
                    NativeCanaryContractError, "authorization-identity-invalid"
                ):
                    new_authorization_state(
                        authorization_id=alias,
                        run_nonce=str(uuid.uuid4()),
                        now="2026-07-17T00:00:00Z",
                        launch_claim_sha256=hash_value("launch"),
                    )

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema") is not None,
        "jsonschema not installed",
    )
    def test_uuid_schema_nodes_require_exact_canonical_text(self) -> None:
        import jsonschema

        schema_paths = (
            "schemas/full-auto-run-authorization.schema.json",
            "schemas/native-canary-authorization-state-v2.schema.json",
            "schemas/native-live-allocation-ledger.schema.json",
            "schemas/native-live-allocation-ledger-v2.schema.json",
            "schemas/native-live-campaign-cause-evidence.schema.json",
            "schemas/native-live-campaign-manifest.schema.json",
            "schemas/native-session-materialization-evidence.schema.json",
            "schemas/native-steering-receipt.schema.json",
            "schemas/native-steering-receipt-v2.schema.json",
        )
        for relative in schema_paths:
            schema = json.loads((ROOT / relative).read_text(encoding="utf-8"))
            pending = [schema]
            uuid_nodes = []
            while pending:
                node = pending.pop()
                if isinstance(node, dict):
                    if node.get("format") == "uuid":
                        uuid_nodes.append(node)
                    pending.extend(node.values())
                elif isinstance(node, list):
                    pending.extend(node)
            self.assertTrue(uuid_nodes, relative)
            for node in uuid_nodes:
                validator = jsonschema.Draft202012Validator(node)
                self.assertTrue(validator.is_valid(CANONICAL_UUID_TEXT), relative)
                for alias in UUID_TEXT_ALIASES:
                    with self.subTest(schema=relative, alias=repr(alias)):
                        self.assertFalse(validator.is_valid(alias))

    def test_rendered_command_requires_exact_production_wrapper(self) -> None:
        expected = validate_capability_rendered_command(
            "/bin/bash -lc 'sleep 20'", raw_command="sleep 20"
        )
        self.assertEqual(len(expected), 64)
        self.assertNotEqual(
            expected,
            validate_capability_rendered_command("sleep 20", raw_command="sleep 20"),
        )
        rejected = (
            "sleep 20 # ignored",
            "sleep 20; touch extra",
            "sleep 20 && true",
            "sleep 20 >/tmp/out",
            "/bin/bash -lc 'sleep 20; true'",
            '/bin/bash -lc "sleep 20"',
            "bash -lc 'sleep 20'",
        )
        for rendered in rejected:
            with (
                self.subTest(rendered=rendered),
                self.assertRaisesRegex(
                    NativeCanaryContractError, "rendered-command-not-exact-wrapper"
                ),
            ):
                validate_capability_rendered_command(rendered, raw_command="sleep 20")

    def test_length_framed_hash_binds_domain_order_type_and_value(self) -> None:
        base = length_framed_sha256(domain="test", fields=(("a", "1"), ("b", 2)))
        variants = (
            length_framed_sha256(domain="other", fields=(("a", "1"), ("b", 2))),
            length_framed_sha256(domain="test", fields=(("b", 2), ("a", "1"))),
            length_framed_sha256(domain="test", fields=(("a", 1), ("b", 2))),
            length_framed_sha256(domain="test", fields=(("a", "1"), ("b", 3))),
        )
        self.assertTrue(all(value != base for value in variants))

    def test_materialization_accepting_happy_path(self) -> None:
        self.assertEqual(
            validate_materialization_evidence(
                materialization(), require_accepting=True
            ),
            [],
        )

    def test_materialization_separation_identity_terminal_and_interrupt_races(
        self,
    ) -> None:
        cases = []
        value = materialization()
        value["liveness_observations"][1]["observed_at"] = "2026-07-16T00:00:01.500Z"
        cases.append((value, "separation"))
        value = materialization()
        value["pre_interrupt_observation"]["function_call_record_index"] = 4
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
        value = materialization()
        value["liveness_observations"][1]["function_call_id_sha256"] = hash_value(
            "other-call"
        )
        cases.append((value, "identity"))
        value = materialization()
        value["pre_interrupt_observation"]["completed_event_count"] = 1
        cases.append((value, "completed_event_count"))
        value = materialization()
        value["liveness_observations"][0]["command_source"] = "agent"
        cases.append((value, "command-source"))
        value = materialization()
        value["liveness_observations"][0]["function_call_count"] = 2
        cases.append((value, "function-call-count"))
        value = materialization()
        value["pre_interrupt_observation"]["execution_correlation_sha256"] = hash_value(
            "other-correlation"
        )
        cases.append((value, "correlation"))
        value = materialization()
        value["liveness_observations"][1]["rendered_command_sha256"] = hash_value(
            "changed-rendering"
        )
        cases.append((value, "identity"))
        value = materialization()
        value["thread_id"] = "other-thread"
        value["interrupt"]["thread_id"] = "other-thread"
        cases.append((value, "session-thread"))
        value = materialization()
        value["liveness_observations"][0]["connection_epoch_sha256"] = hash_value(
            "other-connection"
        )
        cases.append((value, "connection-epoch"))
        value = materialization()
        value["interrupt"]["request_accepted_at"] = "2026-07-16T00:00:02Z"
        cases.append((value, "deadline"))
        for value, expected in cases:
            value = seal_materialization_evidence(value)
            with self.subTest(expected=expected):
                self.assertTrue(
                    any(
                        expected in error
                        for error in validate_materialization_evidence(value)
                    )
                )

    def test_materialization_privacy_unknown_field_and_hash_tamper(self) -> None:
        value = materialization()
        value["raw_prompt"] = "forbidden"
        errors = validate_materialization_evidence(value)
        self.assertIn("materialization-fields-invalid", errors)
        self.assertTrue(any("privacy-key" in error for error in errors))
        value = materialization()
        value["session_id"] = "changed"
        self.assertIn(
            "materialization-evidence-sha256-mismatch",
            validate_materialization_evidence(value),
        )

    def test_materialization_control_sequence_is_strict_and_nontruncating(self) -> None:
        cases = []
        value = materialization()
        value["control_observations"][1]["ordinal"] = 9
        cases.append((value, "ordinal-not-contiguous"))
        value = materialization()
        value["control_observations"][1]["elapsed_monotonic_ms"] = -1
        cases.append((value, "elapsed"))
        value = materialization()
        value["control_observations"][1]["previous_boundary_sha256"] = hash_value(
            "wrong-prefix"
        )
        cases.append((value, "prefix-link"))
        value = materialization()
        value["control_observations"][0]["source_identity_sha256"] = hash_value(
            "replacement-source"
        )
        cases.append((value, "source-identity"))
        value = materialization()
        value["control_observations"][0]["projected_status"] = "interrupted"
        value["control_observations"][0]["decision"] = "continue-active"
        cases.append((value, "provisional-decision"))
        value = materialization()
        value["control_observations"][-1]["decision"] = "interrupt-confirmed"
        cases.append((value, "terminal-observation"))
        value = materialization()
        value["control_observations"][0]["phase"] = "pre-interrupt"
        cases.append((value, "phase-first-invalid"))
        value = materialization()
        value["control_observations"][2]["phase"] = "interrupt-confirmation"
        cases.append((value, "phase-skipped"))
        value = materialization()
        value["control_observations"][3]["phase"] = "materialization"
        cases.append((value, "phase-regressed"))
        value = materialization()
        value["control_observations"][3]["phase"] = "terminal"
        cases.append((value, "terminal-phase-not-singular"))
        value = materialization()
        value["control_observations"][3]["decision"] = "interrupt-pending"
        cases.append((value, "interrupt-confirmation-not-singular"))
        value = materialization()
        extra = dict(value["control_observations"][3])
        extra["ordinal"] = 4
        extra["elapsed_monotonic_ms"] = 875.0
        extra["decision"] = "interrupt-pending"
        extra["previous_boundary_sha256"] = extra["boundary"]["boundary_sha256"]
        value["control_observations"].insert(4, extra)
        value["control_observations"][5]["ordinal"] = 5
        value["control_observations"][5]["previous_boundary_sha256"] = extra[
            "boundary"
        ]["boundary_sha256"]
        cases.append((value, "interrupt-confirmation-not-adjacent-terminal"))
        value = materialization()
        value["control_observations"][2]["decision"] = "terminal-accepted"
        cases.append((value, "terminal-decision-phase-invalid"))
        value = materialization()
        value["liveness_observations"][0]["boundary"] = boundary("unbound-liveness", 5)
        cases.append((value, "liveness-control-binding"))
        value = materialization()
        value["terminal_event"]["event_type"] = "task_complete"
        cases.append((value, "terminal-event-type"))
        value = materialization()
        value["control_observations"] = value["control_observations"] * 40
        cases.append((value, "control-observations-invalid"))
        value = materialization()
        value["control_observations"][0]["raw_status"] = "forbidden"
        cases.append((value, "fields-invalid"))
        for value, expected in cases:
            value = seal_materialization_evidence(value)
            with self.subTest(expected=expected):
                self.assertTrue(
                    any(
                        expected in error
                        for error in validate_materialization_evidence(value)
                    )
                )

    def test_steering_conditional_requires_bound_go_and_replay_is_rejected(
        self,
    ) -> None:
        receipt = steering()
        self.assertIn(
            "steering-receipt-not-accepting",
            validate_steering_receipt(receipt, require_accepting=True),
        )
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
            consumed = json.loads(registry.read_text(encoding="utf-8"))["consumed"][0]
            self.assertEqual(consumed["stop_scope"], "child")
            self.assertEqual(consumed["authorized_continuation_paths"], [])
            with self.assertRaisesRegex(NativeCanaryContractError, "replay"):
                consume_steering_receipt(
                    receipt,
                    registry,
                    phase_nonce=str(uuid.uuid4()),
                    architect_adjudication_sha256=adjudication,
                    architect_decision="go",
                )

    def test_neutral_steering_is_strict_write_with_compatible_v1_read(self) -> None:
        receipt = steering()
        self.assertEqual(
            validate_steering_receipt(receipt, require_neutral=True),
            [],
        )
        final_text = neutral_steering_final_text(receipt)
        self.assertEqual(
            hashlib.sha256(final_text.encode()).hexdigest(),
            receipt["final_response_sha256"],
        )
        historical = historical_steering_receipt()
        self.assertEqual(validate_steering_receipt(historical), [])
        historical_go = historical_steering_receipt()
        historical_go["opinion"]["recommendation"] = "go"
        historical_go["disposition"] = "accepting"
        historical_go["final_response_sha256"] = hashlib.sha256(
            json.dumps(
                historical_go["opinion"], sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
        historical_go.pop("canonical_receipt_sha256")
        historical_go["canonical_receipt_sha256"] = hashlib.sha256(
            json.dumps(historical_go, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertEqual(
            validate_steering_receipt(historical_go, require_accepting=True), []
        )
        self.assertIn(
            "steering-legacy-v1-inspection-only",
            validate_steering_receipt(historical, require_neutral=True),
        )
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(
                NativeCanaryContractError,
                "legacy-v1-inspection-only",
            ),
        ):
            consume_steering_receipt(
                historical,
                Path(temporary) / "registry.json",
                phase_nonce=str(uuid.uuid4()),
                architect_adjudication_sha256=hash_value("adjudication"),
                architect_decision="go",
            )
        tampered = historical_steering_receipt()
        tampered["opinion"]["steering_summary"] = "tampered legacy opinion"
        tampered.pop("canonical_receipt_sha256")
        tampered["canonical_receipt_sha256"] = hashlib.sha256(
            json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertIn(
            "steering-final-response-sha256-mismatch",
            validate_steering_receipt(tampered),
        )
        with self.assertRaisesRegex(
            NativeCanaryContractError, "legacy-v1-inspection-only"
        ):
            steering_stop_metadata(historical)

    def test_neutral_steering_strict_writer_rejects_invalid_envelope(self) -> None:
        cases = (
            (("input",), {}, "steering-input-fields-invalid"),
            (
                ("model_discovery",),
                {},
                "steering-model-discovery-fields-invalid",
            ),
            (("guard",), {}, "steering-guard-fields-invalid"),
            (("boundary",), {}, "steering-boundary-fields-invalid"),
            (("started_at",), "not-a-time", "steering-started-at-invalid"),
            (("gate",), "after-release", "steering-gate-invalid"),
        )
        for path, replacement, expected in cases:
            with self.subTest(path=path):
                receipt = steering()
                target = receipt
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = replacement
                with self.assertRaisesRegex(NativeCanaryContractError, expected):
                    seal_neutral_steering_receipt(receipt)

        changed_guard = steering()
        changed_guard["guard"]["after"]["repo_status_sha256"] = hash_value(
            "changed-status"
        )
        with self.assertRaisesRegex(
            NativeCanaryContractError, "steering-guard-changed"
        ):
            seal_neutral_steering_receipt(changed_guard)

    def test_operator_facts_require_exact_opaque_verified_authority(self) -> None:
        authority = verified_operator_authority()
        receipt = steering()
        receipt["steering"]["operator_facts"] = [
            {
                "statement": OPERATOR_FACT_STATEMENT,
                "authority_provenance": authority.serialize(),
            }
        ]
        receipt = seal_neutral_steering_receipt(
            receipt,
            verified_operator_authorities=[authority],
        )
        self.assertEqual(
            validate_steering_receipt(
                receipt,
                require_neutral=True,
                verified_operator_authorities=[authority],
            ),
            [],
        )
        self.assertIn(
            "steering-operator-fact-0-authority-unverified",
            validate_steering_receipt(receipt, require_neutral=True),
        )
        with self.assertRaisesRegex(
            NativeCanaryContractError,
            "authority-unverified",
        ):
            seal_neutral_steering_receipt(receipt)
        unrelated = copy.deepcopy(receipt)
        unrelated["steering"]["operator_facts"][0]["statement"] = (
            "The operator ordered a publication veto."
        )
        with self.assertRaisesRegex(
            NativeCanaryContractError,
            "authority-action-mismatch",
        ):
            seal_neutral_steering_receipt(
                unrelated,
                verified_operator_authorities=[authority],
            )

    def test_neutral_steering_rejects_conflated_or_asserted_authority_fields(
        self,
    ) -> None:
        base = steering()
        cases = (
            (
                ("steering", "strongest_counterargument"),
                "",
                "steering-strongest-counterargument-invalid",
            ),
            (
                ("steering", "recommendation", "confidence_role"),
                "decision-authority",
                "steering-confidence-role-invalid",
            ),
            (
                ("steering", "agent_authored_constraints", 0, "origin"),
                "operator-authored",
                "steering-agent-constraint-0-origin-invalid",
            ),
            (
                ("stop_scope",),
                "publication",
                "steering-stop-scope-mismatch",
            ),
        )
        for path, replacement, expected in cases:
            with self.subTest(path=path):
                receipt = copy.deepcopy(base)
                target = receipt
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = replacement
                self.assertIn(
                    expected,
                    validate_steering_receipt(receipt, require_neutral=True),
                )

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema") is not None,
        "jsonschema not installed",
    )
    def test_neutral_steering_v2_schema_accepts_strict_writer_output(self) -> None:
        import jsonschema

        schema = json.loads(
            (ROOT / "schemas/native-steering-receipt-v2.schema.json").read_text(
                encoding="utf-8"
            )
        )
        validator = jsonschema.Draft202012Validator(schema)
        validator.validate(steering())
        validator.validate(stop_steering_receipt())
        authority = verified_operator_authority()
        receipt = steering()
        receipt["steering"]["operator_facts"] = [
            {
                "statement": OPERATOR_FACT_STATEMENT,
                "authority_provenance": authority.serialize(),
            }
        ]
        validator.validate(
            seal_neutral_steering_receipt(
                receipt,
                verified_operator_authorities=[authority],
            )
        )
        promoted = stop_steering_receipt()
        promoted["stop_scope"] = "cohort"
        promoted["scope_authority"].update(
            {
                "source_type": "worker-discovery",
                "source_id": "self-asserted-critic",
                "actor_id": "critic",
                "actor_role": "critic",
                "identity_source": "receipt-string",
                "authorized_scope": "cohort",
            }
        )
        promoted["scope_authority"]["verification"]["method"] = (
            "trusted-runtime-role-binding-v1"
        )
        self.assertFalse(validator.is_valid(promoted))

    def test_neutral_steering_payload_tamper_cannot_hide_behind_outer_seal(
        self,
    ) -> None:
        receipt = steering()
        receipt["steering"]["observed_evidence"][0]["observation"] = (
            "tampered observation"
        )
        receipt.pop("canonical_receipt_sha256")
        receipt["canonical_receipt_sha256"] = hashlib.sha256(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        errors = validate_steering_receipt(receipt, require_neutral=True)
        self.assertIn("steering-final-response-sha256-mismatch", errors)
        self.assertNotIn("steering-canonical-sha256-mismatch", errors)

    def test_steering_text_and_confidence_cannot_promote_scope(self) -> None:
        receipt = steering()
        receipt["steering"]["model_interpretation"] = "STOP 0.98 block publication"
        receipt["steering"]["recommendation"]["confidence"] = 0.98
        receipt = seal_neutral_steering_receipt(receipt)
        metadata = steering_stop_metadata(receipt)
        self.assertEqual(metadata["stop_scope"], "child")
        self.assertNotEqual(
            metadata["scope_authority"]["authorized_scope"], "publication"
        )

        stopped = stop_steering_receipt()
        stopped["steering"]["model_interpretation"] = "STOP 0.98 block publication"
        stopped["steering"]["recommendation"]["confidence"] = 0.98
        stopped = seal_neutral_steering_receipt(stopped)
        stopped_metadata = steering_stop_metadata(stopped)
        self.assertEqual(stopped_metadata["stop_scope"], "child")
        self.assertEqual(
            stopped_metadata["scope_authority"]["source_type"],
            "policy-enforcement",
        )
        self.assertEqual(
            stopped_metadata["authorized_continuation_paths"][0]["target_id"],
            stopped["bead_id"],
        )
        self.assertNotEqual(stopped_metadata["stop_scope"], "publication")
        retargeted = copy.deepcopy(stopped)
        retargeted["bead_id"] = "complex-work-orchestration-other-child"
        retargeted = seal_neutral_steering_receipt(retargeted)
        self.assertNotEqual(
            stopped_metadata["scope_authority"]["source_sha256"],
            retargeted["scope_authority"]["source_sha256"],
        )
        self.assertEqual(
            retargeted["authorized_continuation_paths"][0]["target_id"],
            retargeted["bead_id"],
        )

    def test_v2_go_remains_advisory_until_bound_architect_go(self) -> None:
        receipt = steering()
        receipt["steering"]["recommendation"]["outcome"] = "go"
        receipt["disposition"] = "accepting"
        receipt = seal_neutral_steering_receipt(receipt)
        self.assertIn(
            "steering-receipt-not-accepting",
            validate_steering_receipt(receipt, require_accepting=True),
        )
        adjudication_sha256 = hash_value("architect-go")
        self.assertEqual(
            validate_steering_receipt(
                receipt,
                architect_adjudication_sha256=adjudication_sha256,
                architect_decision="go",
                require_accepting=True,
            ),
            [],
        )
        with tempfile.TemporaryDirectory() as temporary:
            registry = Path(temporary) / "registry.json"
            with self.assertRaisesRegex(
                NativeCanaryContractError, "steering-receipt-not-accepting"
            ):
                consume_steering_receipt(
                    receipt,
                    registry,
                    phase_nonce=str(uuid.uuid4()),
                    architect_adjudication_sha256="garbage",
                    architect_decision="go",
                )
            self.assertFalse(registry.exists())
            consume_steering_receipt(
                receipt,
                registry,
                phase_nonce=str(uuid.uuid4()),
                architect_adjudication_sha256=adjudication_sha256,
                architect_decision="go",
            )

    def test_steering_stop_pre_mutation_requires_resolved_main_architect_adjudication(
        self,
    ) -> None:
        receipt = stop_steering_receipt()
        adjudication = resolved_stop_adjudication(receipt)
        adjudication_hash = "a" * 64
        head = "d" * 40
        self.assertIn(
            "steering-receipt-not-accepting",
            validate_steering_receipt(receipt, require_accepting=True),
        )
        self.assertEqual(
            validate_steering_receipt(
                receipt,
                architect_adjudication_sha256=adjudication_hash,
                architect_decision="go",
                allow_resolved_stop=True,
                resolved_stop_adjudication=adjudication,
                resolved_stop_post_resolution_commit=head,
                require_accepting=True,
            ),
            [],
        )
        with tempfile.TemporaryDirectory() as temporary:
            registry = Path(temporary) / "consumed.json"
            kwargs = {
                "phase_nonce": str(uuid.uuid4()),
                "architect_adjudication_sha256": adjudication_hash,
                "architect_decision": "go",
                "allow_resolved_stop": True,
                "resolved_stop_adjudication": adjudication,
                "resolved_stop_post_resolution_commit": head,
            }
            consume_steering_receipt(receipt, registry, **kwargs)
            kwargs["phase_nonce"] = str(uuid.uuid4())
            with self.assertRaisesRegex(NativeCanaryContractError, "replay"):
                consume_steering_receipt(receipt, registry, **kwargs)

    def test_steering_stop_pre_mutation_malformed_resolution_cases(self) -> None:
        base_receipt = stop_steering_receipt()
        base_adjudication = resolved_stop_adjudication(base_receipt)
        base_hash = "a" * 64
        head = "d" * 40
        cases = (
            ({"schema": "wrong"}, "steering-stop-adjudication-schema-invalid"),
            ({"gate": "pre-live"}, "steering-stop-adjudication-gate-invalid"),
            (
                {"steering_receipt_canonical_sha256": "f" * 64},
                "steering-stop-adjudication-receipt-mismatch",
            ),
            (
                {
                    "resolved_findings": [
                        {"code": "A-1", "severity": "high", "status": "unresolved"}
                    ]
                },
                "steering-stop-adjudication-finding-invalid",
            ),
            (
                {
                    "resolved_findings": [
                        {"code": "A-1", "severity": "high", "status": "resolved"},
                        {"code": "Z", "severity": "medium", "status": "resolved"},
                    ]
                },
                "steering-stop-adjudication-finding-codes-mismatch",
            ),
            (
                {"unresolved_high_severity_findings": ["A-1"]},
                "steering-stop-adjudication-findings-unresolved",
            ),
            (
                {"post_resolution_commit": "e" * 40},
                "steering-stop-adjudication-post-commit-mismatch",
            ),
            (
                {"resolution_evidence_sha256": "g"},
                "steering-stop-adjudication-evidence-digest-invalid",
            ),
            (
                {"pre_live_reconfirmation_required": False},
                "steering-stop-adjudication-reconfirmation-required-missing",
            ),
            (
                {"post_resolution_commit": "d" * 41},
                "steering-stop-adjudication-post-commit-invalid",
            ),
        )
        for mutation, expected in cases:
            with self.subTest(mutation=mutation):
                adjudication = copy.deepcopy(base_adjudication)
                adjudication.update(mutation)
                errors = validate_steering_receipt(
                    base_receipt,
                    architect_adjudication_sha256=base_hash,
                    architect_decision="go",
                    allow_resolved_stop=True,
                    resolved_stop_adjudication=adjudication,
                    resolved_stop_post_resolution_commit=head,
                    require_accepting=True,
                )
                self.assertIn(expected, errors)

        errors = validate_steering_receipt(
            base_receipt,
            architect_adjudication_sha256=base_hash,
            architect_decision="conditional-go",
            allow_resolved_stop=True,
            resolved_stop_adjudication=base_adjudication,
            resolved_stop_post_resolution_commit=head,
            require_accepting=True,
        )
        self.assertIn("steering-stop-main-adjudication-not-bound-go", errors)

        pre_live_receipt = copy.deepcopy(base_receipt)
        pre_live_receipt["gate"] = "pre-live"
        pre_live_receipt["canonical_receipt_sha256"] = hashlib.sha256(
            json.dumps(
                {
                    k: v
                    for k, v in pre_live_receipt.items()
                    if k != "canonical_receipt_sha256"
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        pre_live_adjudication = resolved_stop_adjudication(pre_live_receipt)
        errors = validate_steering_receipt(
            pre_live_receipt,
            architect_adjudication_sha256=base_hash,
            architect_decision="go",
            allow_resolved_stop=True,
            resolved_stop_adjudication=pre_live_adjudication,
            resolved_stop_post_resolution_commit=head,
            require_accepting=True,
        )
        self.assertIn("steering-stop-receipt-gate-invalid", errors)

    def test_steering_stop_pre_mutation_unknown_adjudication_fields_reject(
        self,
    ) -> None:
        receipt = stop_steering_receipt()
        adjudication = resolved_stop_adjudication(receipt)
        adjudication["unexpected"] = "extra"
        errors = validate_steering_receipt(
            receipt,
            architect_adjudication_sha256="a" * 64,
            architect_decision="go",
            allow_resolved_stop=True,
            resolved_stop_adjudication=adjudication,
            resolved_stop_post_resolution_commit="d" * 40,
            require_accepting=True,
        )
        self.assertIn("steering-stop-adjudication-fields-invalid", errors)

    def test_steering_stop_pre_mutation_reconciles_missing_required_findings(
        self,
    ) -> None:
        receipt = stop_steering_receipt()
        adjudication = resolved_stop_adjudication(receipt)
        adjudication["resolved_findings"] = [
            {"code": "A-1", "severity": "high", "status": "resolved"},
        ]
        errors = validate_steering_receipt(
            receipt,
            architect_adjudication_sha256="a" * 64,
            architect_decision="go",
            allow_resolved_stop=True,
            resolved_stop_adjudication=adjudication,
            resolved_stop_post_resolution_commit="d" * 40,
            require_accepting=True,
        )
        self.assertIn("steering-stop-adjudication-finding-codes-mismatch", errors)

    def test_steering_stop_pre_mutation_rejects_duplicate_receipt_finding_codes(
        self,
    ) -> None:
        receipt = stop_steering_receipt()
        receipt["steering"]["observed_evidence"].insert(
            1,
            {
                "severity": "medium",
                "code": "A-1",
                "observation": "duplicate code",
                "evidence_sha256": hash_value("duplicate-A-1"),
            },
        )
        adjudication = resolved_stop_adjudication(receipt)
        errors = validate_steering_receipt(
            receipt,
            architect_adjudication_sha256="a" * 64,
            architect_decision="go",
            allow_resolved_stop=True,
            resolved_stop_adjudication=adjudication,
            resolved_stop_post_resolution_commit="d" * 40,
            require_accepting=True,
        )
        self.assertIn("steering-stop-receipt-finding-codes-duplicate", errors)

    def test_steering_model_activity_boundary_and_hash_tamper(self) -> None:
        receipt = steering()
        receipt["model"] = "other"
        self.assertIn(
            "steering-model-effort-mismatch", validate_steering_receipt(receipt)
        )
        receipt = steering()
        receipt["observed_activity"]["function_calls"] = 1
        self.assertIn("steering-nonzero-activity", validate_steering_receipt(receipt))
        receipt = steering()
        receipt["boundary"]["terminal"]["trailing_partial"] = True
        self.assertIn(
            "steering-terminal-boundary-not-clean", validate_steering_receipt(receipt)
        )
        receipt = steering()
        receipt["gate"] = "changed"
        self.assertIn(
            "steering-canonical-sha256-mismatch", validate_steering_receipt(receipt)
        )

    def test_authorization_latch_is_private_monotonic_and_revokes_delayed_actions(
        self,
    ) -> None:
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
            self.assertEqual(
                store.require_action("tracked-mutation")["state"], "active"
            )
            contained = store.transition(
                "containment-only", reason="protected-fault", now="2026-07-16T00:00:01Z"
            )
            self.assertEqual(contained["sequence"], 1)
            self.assertIn("tracked-mutation", contained["revoked_actions"])
            self.assertEqual(
                store.require_action("interrupt")["state"], "containment-only"
            )
            for action in (
                "retry",
                "relaunch",
                "tracked-mutation",
                "release-enable",
                "push",
                "install",
                "publish",
            ):
                with (
                    self.subTest(action=action),
                    self.assertRaisesRegex(NativeCanaryContractError, "revoked"),
                ):
                    store.require_action(action)
            with self.assertRaisesRegex(
                NativeCanaryContractError, "transition-forbidden"
            ):
                store.transition(
                    "active", reason="late-event", now="2026-07-16T00:00:02Z"
                )
            parked = store.transition(
                "parked", reason="evidence-durable", now="2026-07-16T00:00:03Z"
            )
            self.assertEqual(parked["state"], "parked")

    def test_authorization_complete_is_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = CanaryAuthorizationStore(Path(temporary) / "authorization.json")
            store.initialize(
                new_authorization_state(
                    authorization_id="a", run_nonce="r", now="2026-07-16T00:00:00Z"
                )
            )
            completed = store.transition(
                "complete", reason="accepted", now="2026-07-16T00:00:01Z"
            )
            self.assertEqual(completed["allowed_actions"], [])
            with self.assertRaisesRegex(
                NativeCanaryContractError, "transition-forbidden"
            ):
                store.transition(
                    "containment-only", reason="late", now="2026-07-16T00:00:02Z"
                )

    def test_v2_launch_claim_is_atomic_and_survives_transitions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "authorization.json"
            launch_claim = hash_value("generation-seven-launch")
            authorization_id = str(uuid.uuid4())

            def claim() -> str:
                try:
                    CanaryAuthorizationStore(path).initialize(
                        new_authorization_state(
                            authorization_id=authorization_id,
                            run_nonce=str(uuid.uuid4()),
                            now="2026-07-17T00:00:00Z",
                            launch_claim_sha256=launch_claim,
                        )
                    )
                except NativeCanaryContractError as exc:
                    return str(exc)
                return "won"

            with ThreadPoolExecutor(max_workers=2) as executor:
                outcomes = list(executor.map(lambda _index: claim(), range(2)))
            self.assertEqual(outcomes.count("won"), 1)
            self.assertEqual(
                sum("authorization-state-already-exists" in item for item in outcomes),
                1,
            )
            store = CanaryAuthorizationStore(path)
            active = store.load()
            self.assertEqual(active["version"], 2)
            self.assertEqual(active["launch_claim_sha256"], launch_claim)
            contained = store.transition(
                "containment-only",
                reason="protected-fault",
                now="2026-07-17T00:00:01Z",
            )
            self.assertEqual(contained["launch_claim_sha256"], launch_claim)
            tampered = dict(contained)
            tampered["launch_claim_sha256"] = hash_value("different-launch")
            self.assertIn(
                "authorization-state-sha256-mismatch",
                validate_authorization_state(tampered),
            )

    def test_schemas_are_json_and_strict(self) -> None:
        for relative in (
            "schemas/native-steering-receipt.schema.json",
            "schemas/native-steering-receipt-v2.schema.json",
            MATERIALIZATION_EVIDENCE_SCHEMA,
            CANARY_AUTHORIZATION_SCHEMA,
            "schemas/native-canary-authorization-state-v2.schema.json",
        ):
            value = json.loads((ROOT / relative).read_text(encoding="utf-8"))
            self.assertFalse(value["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
