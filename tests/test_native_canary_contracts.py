from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
import uuid
from typing import NamedTuple


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_canary_contracts import (  # noqa: E402
    MATERIALIZATION_EVIDENCE_SCHEMA,
    MATERIALIZATION_EVIDENCE_TYPE,
    NativeCanaryContractError,
    canonical_sha256,
    length_framed_sha256,
    materialization_execution_correlation,
    materialization_liveness_correlation,
    seal_materialization_evidence,
    validate_capability_rendered_command,
    validate_materialization_evidence,
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
    correlation = materialization_liveness_correlation(
        connection_epoch_sha256=hash_value("connection"),
        session_id=session,
        thread_id=thread,
        turn_id=turn,
        command_item_id_sha256=command_item,
        notification_sequence=4,
        notification_received_monotonic_ns=100,
        notification_started_at_ms=42,
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
        "correlation_mode": "session-and-notification",
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


def notification_shape(session: str, turn: str) -> dict:
    body = {
        "evidence_type": "cwo-app-server-notification-shape:v1",
        "version": 1,
        "connection_epoch_sha256": hash_value("connection"),
        "thread_id_sha256": hash_value(session),
        "turn_id_sha256": hash_value(turn),
        "event_count": 1,
        "events": [
            {
                "sequence": 4,
                "received_monotonic_ns": 100,
                "method": "item/started",
                "params_keys": ["item", "startedAtMs", "threadId", "turnId"],
                "item_keys": ["command", "cwd", "id", "source", "status", "type"],
                "thread_id_matches": True,
                "turn_id_matches": True,
                "item_type": "commandExecution",
                "item_status": "inProgress",
                "item_namespace": None,
                "item_tool": None,
                "item_id_sha256": hash_value("item"),
                "payload_digest_sha256": hash_value("payload"),
                "started_at_ms_type": "integer",
            }
        ],
    }
    body["evidence_sha256"] = canonical_sha256(
        body, domain="native-app-server-notification-shape"
    )
    return body


def terminal_execution_correlation(session: str, turn: str) -> dict:
    rendered = validate_capability_rendered_command(
        "/bin/bash -lc 'sleep 20'", raw_command="sleep 20"
    )
    value = {
        "turn_context_record_index": 2,
        "function_call_record_index": 3,
        "function_call_id_sha256": hash_value("call"),
        "command_item_id_sha256": hash_value("item"),
        "notification_sequence": 4,
        "notification_received_monotonic_ns": 100,
        "notification_started_at_ms": 42,
        "rendered_command_sha256": rendered,
    }
    value["execution_correlation_sha256"] = materialization_execution_correlation(
        connection_epoch_sha256=hash_value("connection"),
        session_id=session,
        thread_id=session,
        turn_id=turn,
        command_item_id_sha256=value["command_item_id_sha256"],
        function_call_id_sha256=value["function_call_id_sha256"],
        notification_sequence=value["notification_sequence"],
        notification_received_monotonic_ns=value["notification_received_monotonic_ns"],
        notification_started_at_ms=value["notification_started_at_ms"],
        turn_context_record_index=value["turn_context_record_index"],
        function_call_record_index=value["function_call_record_index"],
        rendered_command_sha256=rendered,
        raw_command_sha256=hash_value("sleep 20"),
    )
    return value


def materialization() -> dict:
    session = "session-one"
    turn = "turn-one"
    return seal_materialization_evidence(
        {
            "evidence_type": MATERIALIZATION_EVIDENCE_TYPE,
            "version": 5,
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
            "notification_shape": notification_shape(session, turn),
            "terminal_execution_correlation": terminal_execution_correlation(
                session, turn
            ),
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


class CanarySchemaRow(NamedTuple):
    original_id: str
    contract: str


class MaterializationRow(NamedTuple):
    original_id: str
    value: dict
    reseal: bool
    contract: str
    expected: str | None = None


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

    def test_materialization_decision_family(self) -> None:
        cases = [MaterializationRow(
            "tests.test_native_canary_contracts.NativeCanaryContractTests.test_materialization_accepting_happy_path",
            materialization(), False, "accepting")]
        original_id = "tests.test_native_canary_contracts.NativeCanaryContractTests.test_materialization_privacy_unknown_field_and_hash_tamper"
        value = materialization()
        value["raw_prompt"] = "forbidden"
        cases.append(MaterializationRow(original_id, value, False, "privacy"))
        value = materialization()
        value["session_id"] = "changed"
        cases.append(MaterializationRow(original_id, value, False, "hash"))
        original_id = 'tests.test_native_canary_contracts.NativeCanaryContractTests.test_materialization_separation_identity_terminal_and_interrupt_races'
        value = materialization()
        value["liveness_observations"][1]["observed_at"] = "2026-07-16T00:00:01.500Z"
        cases.append(MaterializationRow(original_id, value, True, "fragment", "separation"))
        value = materialization()
        value["pre_interrupt_observation"]["function_call_record_index"] = 4
        cases.append(MaterializationRow(original_id, value, True, "fragment", "identity"))
        value = materialization()
        value["liveness_observations"][0]["terminal_event_count"] = 1
        cases.append(MaterializationRow(original_id, value, True, "fragment", "terminal"))
        value = materialization()
        value["liveness_observations"][0]["command_status"] = "failed"
        cases.append(MaterializationRow(original_id, value, True, "fragment", "command"))
        value = materialization()
        value["interrupt"]["turn_id"] = "other"
        cases.append(MaterializationRow(original_id, value, True, "fragment", "interrupt-identity"))
        value = materialization()
        value["interrupt"]["confirmed_at"] = "2026-07-16T00:00:09Z"
        cases.append(MaterializationRow(original_id, value, True, "fragment", "deadline"))
        value = materialization()
        value["liveness_observations"][1]["function_call_id_sha256"] = hash_value(
            "other-call"
        )
        cases.append(MaterializationRow(original_id, value, True, "fragment", "identity"))
        value = materialization()
        value["pre_interrupt_observation"]["completed_event_count"] = 1
        cases.append(MaterializationRow(original_id, value, True, "fragment", "completed_event_count"))
        value = materialization()
        value["liveness_observations"][0]["command_source"] = "agent"
        cases.append(MaterializationRow(original_id, value, True, "fragment", "command-source"))
        value = materialization()
        value["liveness_observations"][0]["function_call_count"] = 2
        cases.append(MaterializationRow(original_id, value, True, "fragment", "function-call-count"))
        value = materialization()
        value["pre_interrupt_observation"]["execution_correlation_sha256"] = hash_value(
            "other-correlation"
        )
        cases.append(MaterializationRow(original_id, value, True, "fragment", "correlation"))
        value = materialization()
        value["liveness_observations"][1]["rendered_command_sha256"] = hash_value(
            "changed-rendering"
        )
        cases.append(MaterializationRow(original_id, value, True, "fragment", "identity"))
        value = materialization()
        value["thread_id"] = "other-thread"
        value["interrupt"]["thread_id"] = "other-thread"
        cases.append(MaterializationRow(original_id, value, True, "fragment", "session-thread"))
        value = materialization()
        value["liveness_observations"][0]["connection_epoch_sha256"] = hash_value(
            "other-connection"
        )
        cases.append(MaterializationRow(original_id, value, True, "fragment", "connection-epoch"))
        value = materialization()
        value["interrupt"]["request_accepted_at"] = "2026-07-16T00:00:02Z"
        cases.append(MaterializationRow(original_id, value, True, "fragment", "deadline"))
        original_id = 'tests.test_native_canary_contracts.NativeCanaryContractTests.test_materialization_control_sequence_is_strict_and_nontruncating'
        value = materialization()
        value["control_observations"][1]["ordinal"] = 9
        cases.append(MaterializationRow(original_id, value, True, "fragment", "ordinal-not-contiguous"))
        value = materialization()
        value["control_observations"][1]["elapsed_monotonic_ms"] = -1
        cases.append(MaterializationRow(original_id, value, True, "fragment", "elapsed"))
        value = materialization()
        value["control_observations"][1]["previous_boundary_sha256"] = hash_value(
            "wrong-prefix"
        )
        cases.append(MaterializationRow(original_id, value, True, "fragment", "prefix-link"))
        value = materialization()
        value["control_observations"][0]["source_identity_sha256"] = hash_value(
            "replacement-source"
        )
        cases.append(MaterializationRow(original_id, value, True, "fragment", "source-identity"))
        value = materialization()
        value["control_observations"][0]["projected_status"] = "interrupted"
        value["control_observations"][0]["decision"] = "continue-active"
        cases.append(MaterializationRow(original_id, value, True, "fragment", "provisional-decision"))
        value = materialization()
        value["control_observations"][-1]["decision"] = "interrupt-confirmed"
        cases.append(MaterializationRow(original_id, value, True, "fragment", "terminal-observation"))
        value = materialization()
        value["control_observations"][0]["phase"] = "pre-interrupt"
        cases.append(MaterializationRow(original_id, value, True, "fragment", "phase-first-invalid"))
        value = materialization()
        value["control_observations"][2]["phase"] = "interrupt-confirmation"
        cases.append(MaterializationRow(original_id, value, True, "fragment", "phase-skipped"))
        value = materialization()
        value["control_observations"][3]["phase"] = "materialization"
        cases.append(MaterializationRow(original_id, value, True, "fragment", "phase-regressed"))
        value = materialization()
        value["control_observations"][3]["phase"] = "terminal"
        cases.append(MaterializationRow(original_id, value, True, "fragment", "terminal-phase-not-singular"))
        value = materialization()
        value["control_observations"][3]["decision"] = "interrupt-pending"
        cases.append(MaterializationRow(original_id, value, True, "fragment", "interrupt-confirmation-not-singular"))
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
        cases.append(MaterializationRow(original_id, value, True, "fragment", "interrupt-confirmation-not-adjacent-terminal"))
        value = materialization()
        value["control_observations"][2]["decision"] = "terminal-accepted"
        cases.append(MaterializationRow(original_id, value, True, "fragment", "terminal-decision-phase-invalid"))
        value = materialization()
        value["liveness_observations"][0]["boundary"] = boundary("unbound-liveness", 5)
        cases.append(MaterializationRow(original_id, value, True, "fragment", "liveness-control-binding"))
        value = materialization()
        value["terminal_event"]["event_type"] = "task_complete"
        cases.append(MaterializationRow(original_id, value, True, "fragment", "terminal-event-type"))
        value = materialization()
        value["control_observations"] = value["control_observations"] * 40
        cases.append(MaterializationRow(original_id, value, True, "fragment", "control-observations-invalid"))
        value = materialization()
        value["control_observations"][0]["raw_status"] = "forbidden"
        cases.append(MaterializationRow(original_id, value, True, "fragment", "fields-invalid"))
        for row in cases:
            value = seal_materialization_evidence(row.value) if row.reseal else row.value
            options = {"require_accepting": True} if row.contract == "accepting" else {}
            with self.subTest(original_id=row.original_id, expected=row.expected):
                errors = validate_materialization_evidence(value, **options)
                if row.contract == "accepting":
                    self.assertEqual(errors, [])
                elif row.contract == "privacy":
                    self.assertIn("materialization-fields-invalid", errors)
                    self.assertTrue(any("privacy-key" in error for error in errors))
                elif row.contract == "hash":
                    self.assertIn("materialization-evidence-sha256-mismatch", errors)
                else:
                    self.assertTrue(any(row.expected in error for error in errors))


    def test_notification_first_requires_later_durable_session_correlation(self) -> None:
        value = materialization()
        for item in [
            *value["liveness_observations"],
            value["pre_interrupt_observation"],
        ]:
            item["correlation_mode"] = "notification-first"
            item["turn_context_record_index"] = None
            item["function_call_record_index"] = None
            item["function_call_id_sha256"] = None
            item["function_call_count"] = 0
            item["command_source"] = "namespacedExecStartup"
        value = seal_materialization_evidence(value)
        self.assertEqual(
            validate_materialization_evidence(value, require_accepting=True),
            [],
        )
        value["terminal_execution_correlation"]["function_call_id_sha256"] = (
            hash_value("substitute-call")
        )
        value = seal_materialization_evidence(value)
        self.assertIn(
            "materialization-terminal-execution-correlation-mismatch",
            validate_materialization_evidence(value, require_accepting=True),
        )

    def test_canary_schema_oracle_family(self) -> None:
        rows = (
            CanarySchemaRow("tests.test_native_canary_contracts.NativeCanaryContractTests.test_schemas_are_json_and_strict", "strict"),
            CanarySchemaRow("tests.test_native_canary_contracts.NativeCanaryContractTests.test_materialization_schema_matches_both_trusted_command_sources", "command-sources"),
        )
        for relative in (
            "schemas/native-steering-receipt.schema.json",
            "schemas/native-steering-receipt-v2.schema.json",
            MATERIALIZATION_EVIDENCE_SCHEMA,
            "schemas/native-canary-authorization-state.schema.json",
            "schemas/native-canary-authorization-state-v2.schema.json",
        ):
            schema = json.loads((ROOT / relative).read_text(encoding="utf-8"))
            for row in rows:
                if row.contract == "strict" or relative == MATERIALIZATION_EVIDENCE_SCHEMA:
                    with self.subTest(original_id=row.original_id, schema=relative):
                        if row.contract == "strict":
                            self.assertFalse(schema["additionalProperties"])
                        else:
                            self.assertEqual(schema["$defs"]["observation"]["properties"]["command_source"],
                                             {"enum": ["unifiedExecStartup", "namespacedExecStartup"]})




if __name__ == "__main__":
    unittest.main()
