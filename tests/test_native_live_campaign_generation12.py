from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import uuid
import unittest
from unittest.mock import patch

from scripts.cwo_core import native_live_campaign_contracts as CONTRACTS


ROOT = Path(__file__).resolve().parents[1]


def snapshot(value: dict) -> CONTRACTS.JsonArtifactSnapshot:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return CONTRACTS.JsonArtifactSnapshot(raw=raw, value=value)


class Generation12ContractTests(unittest.TestCase):
    @staticmethod
    def _jsonl(records: list[dict]) -> bytes:
        return b"".join(
            (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
            for record in records
        )

    @staticmethod
    def _reseal(value: dict, field: str) -> CONTRACTS.JsonArtifactSnapshot:
        unsigned = deepcopy(value)
        unsigned.pop(field, None)
        unsigned[field] = CONTRACTS.canonical_sha256(unsigned)
        return snapshot(unsigned)

    def terminal_fixture(self) -> tuple[
        CONTRACTS.JsonArtifactSnapshot,
        dict,
        dict,
        dict,
        dict,
        bytes,
        dict,
    ]:
        authorization_id = str(uuid.uuid4())
        manifest_id = str(uuid.uuid4())
        nonce = str(uuid.uuid4())
        session_id = str(uuid.uuid4())
        turn_id = str(uuid.uuid4())
        terminal_payload = {
            "type": "turn_aborted",
            "turn_id": turn_id,
            "reason": "interrupted",
            "completed_at": 1,
            "duration_ms": 1,
        }
        records = [
            {"type": "session_meta", "payload": {"id": session_id}},
            {
                "type": "event_msg",
                "payload": {"type": "task_started", "turn_id": turn_id},
            },
            {
                "type": "response_item",
                "payload": {"type": "message", "role": "developer"},
            },
            {
                "type": "response_item",
                "payload": {"type": "message", "role": "user"},
            },
            {"type": "world_state", "payload": {}},
            {
                "type": "turn_context",
                "payload": {
                    "turn_id": turn_id,
                    "model": CONTRACTS.EXACT_OPERATIVE_MODEL,
                    "effort": CONTRACTS.EXACT_OPERATIVE_EFFORT,
                },
            },
            {
                "type": "response_item",
                "payload": {"type": "message", "role": "user"},
            },
            {"type": "event_msg", "payload": {"type": "user_message"}},
            {
                "type": "response_item",
                "payload": {"type": "message", "role": "user"},
            },
            {"type": "event_msg", "payload": terminal_payload},
        ]
        session = b"".join(
            (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
            for record in records
        )
        session_sha256 = hashlib.sha256(session).hexdigest()
        event_sha256 = CONTRACTS._generation11_fact_sha256(
            terminal_payload, leaf="interrupted-terminal-event"
        )
        ledger = {
            "entries": [
                {
                    "event": "thread-bound",
                    "thread_id": session_id,
                    "turn_id": None,
                },
                {
                    "event": "turn-bound",
                    "thread_id": session_id,
                    "turn_id": turn_id,
                },
            ]
        }
        prior_authorization = {
            "authorization_id": authorization_id,
            "bindings": {"campaign_nonce": nonce},
        }
        prior_manifest = {"manifest_id": manifest_id}
        failure = {
            "failure_message_sha256": CONTRACTS.GENERATION11_FAILURE_MESSAGE_SHA256
        }
        containment = {
            "allocation_ledger": {},
            "bead_id": "epic",
            "canonical_recovery_sha256": "",
            "claim_v5_and_scope": {},
            "contained_session": {
                "active_match_count": 0,
                "archive_match_count": 1,
                "assistant_messages": 0,
                "attested_effort": CONTRACTS.EXACT_OPERATIVE_EFFORT,
                "attested_model": CONTRACTS.EXACT_OPERATIVE_MODEL,
                "byte_offset": len(session),
                "compactions": 0,
                "custom_tool_calls": 0,
                "file_sha256": session_sha256,
                "function_calls": 0,
                "patch_events": 0,
                "record_count": len(records),
                "reroutes": 0,
                "session_id": session_id,
                "store": "archived_sessions",
                "terminal_event": {
                    "count": 1,
                    "event_type": "turn_aborted",
                    "record_index": len(records) - 1,
                    "status": "interrupted",
                },
                "trusted_turn_context_count": 1,
                "turn_context_record_index": 5,
                "turn_id": turn_id,
                "workspace_mutation_evidence": "zero-tool-plus-stable-checkout-guards",
            },
            "containment": {},
            "control_plane_recheck": {
                "cap_two_operative_release": False,
                "current_successor_implementation_in_progress": True,
                "failure_time_tracked_clean": True,
                "isolated_checkout_head": "a" * 40,
                "isolated_checkout_tree": "b" * 40,
                "native_supervision_pool_status": "canary-gated",
                "operative_dispatch_authorized": False,
                "origin_main_commit": "c" * 40,
                "protected_primary_diff_sha256": "d" * 64,
                "release_gate_passed": False,
                "transient_successor_worktree_diff_bound": False,
                "workspace_mutations_observed": 0,
            },
            "control_turn_id": "control",
            "disposition": {
                "authorization_state": "containment-only",
                "generation11_retry_resume_substitute_bridge_salvage": False,
                "generation11_state": "terminal-contained",
                "glm_5_2_used": False,
                "model_synthesis_used": False,
                "operative_dispatch_authorized": False,
                "publish_push_install_authorized": False,
                "release_gate_passed": False,
                "requires_fresh_live_generation": 12,
            },
            "failed_authority": {
                "authorization_canonical_sha256": "1" * 64,
                "authorization_file_sha256": "2" * 64,
                "authorization_id": authorization_id,
                "authorization_version": 10,
                "campaign_nonce": nonce,
                "live_generation": 11,
                "manifest_canonical_sha256": "3" * 64,
                "manifest_file_sha256": "4" * 64,
                "manifest_id": manifest_id,
                "manifest_version": 7,
                "outer_authority_canonical_sha256": "5" * 64,
                "outer_authority_file_sha256": "6" * 64,
                "outer_authority_id": str(uuid.uuid4()),
                "run_generation": 23,
            },
            "generation12_recovery_contract": {
                "accepted_finding_codes": ["TERMINAL_LEAVES"],
                "cause_analysis_file_sha256": "7" * 64,
                "fresh_authority_required": True,
                "implementation_conditions_are_mandatory": True,
                "live_launch_authorized_by_this_artifact": False,
                "required_authorization_version": 11,
                "required_launch_claim_version": 6,
                "required_manifest_version": 8,
                "required_validator_version": 6,
                "sol_confidence": 0.94,
                "sol_receipt_canonical_sha256": "8" * 64,
                "sol_receipt_file_sha256": "9" * 64,
                "sol_recommendation": "conditional-go",
                "sol_session": {},
            },
            "recorded_at": "2026-07-18T13:00:00Z",
            "root_cause": {
                "cause_class": "empty-materialized-session-boundary-rejected",
                "existing_zero_byte_session_boundary_accepted": False,
                "failed_edge": "capability-read-recovery:at-fault",
                "independently_reproduced_failure_message_hash": True,
                "missing_session_boundary_accepted": True,
                "replacement_read_attempted": False,
                "source_analysis_file_sha256": "a" * 64,
            },
            "schema": "cwo-live-campaign-containment-recovery:v5",
            "steering_consumptions": {},
            "terminal_failure": {
                "failure_class": "AppServerError",
                "failure_code": "AppServerError",
                "failure_evidence_canonical_sha256": "b" * 64,
                "failure_evidence_file_sha256": "c" * 64,
                "failure_message": "capability-read-recovery-fault-boundary-invalid:session file has no complete records",
                "failure_message_sha256": CONTRACTS.GENERATION11_FAILURE_MESSAGE_SHA256,
                "first_protected_fault": None,
                "validation_outcome": "rejected",
            },
            "version": 5,
        }
        containment["canonical_recovery_sha256"] = CONTRACTS.canonical_sha256(
            {
                key: value
                for key, value in containment.items()
                if key != "canonical_recovery_sha256"
            }
        )
        containment_snapshot = snapshot(containment)
        bindings = {
            "predecessor_authorization_file_sha256": "2" * 64,
            "predecessor_authorization_canonical_sha256": "1" * 64,
            "predecessor_manifest_file_sha256": "4" * 64,
            "predecessor_manifest_canonical_sha256": "3" * 64,
            "predecessor_failure_evidence_file_sha256": "c" * 64,
            "predecessor_failure_evidence_canonical_sha256": "b" * 64,
            "predecessor_containment_file_sha256": containment_snapshot.raw_sha256,
            "predecessor_containment_canonical_sha256": containment[
                "canonical_recovery_sha256"
            ],
            "predecessor_terminal_session_file_sha256": session_sha256,
            "predecessor_terminal_session_id": session_id,
            "predecessor_terminal_turn_id": turn_id,
            "predecessor_initial_empty_boundary_sha256": (
                CONTRACTS._generation11_fact_sha256(
                    CONTRACTS.GENERATION11_INITIAL_EMPTY_BOUNDARY,
                    leaf="initial-empty-boundary",
                )
            ),
            "predecessor_recovery_entry_sha256": (
                CONTRACTS._generation11_fact_sha256(
                    CONTRACTS.GENERATION11_RECOVERY_ENTRY,
                    leaf="recovery-entry",
                )
            ),
            "predecessor_interrupted_terminal_event_sha256": event_sha256,
            "predecessor_no_replacement_read_sha256": (
                CONTRACTS._generation11_fact_sha256(
                    CONTRACTS.GENERATION11_NO_REPLACEMENT_READ,
                    leaf="no-replacement-read",
                )
            ),
        }
        return (
            containment_snapshot,
            bindings,
            prior_authorization,
            prior_manifest,
            failure,
            session,
            ledger,
        )

    def terminal_facts_fixture(self) -> tuple[
        CONTRACTS.Version10InterruptedEmptyBoundaryPredecessorProofInputs,
        dict,
        dict,
        dict,
        dict,
        tuple[str, str],
    ]:
        (
            _containment,
            terminal_bindings,
            prior_authorization,
            _prior_manifest,
            failure,
            terminal_session,
            _ledger,
        ) = self.terminal_fixture()
        authorization_id = prior_authorization["authorization_id"]
        manifest_id = str(uuid.uuid4())
        control_turn_id = str(uuid.uuid4())
        bead_id = "complex-work-orchestration-fsh.2.6.50"
        work_unit_id = "complex-work-orchestration-fsh.2.6.52"
        authorization = {
            "authorization_id": authorization_id,
            "bindings": {
                "campaign_nonce": prior_authorization["bindings"]["campaign_nonce"]
            },
        }
        manifest = {
            "manifest_id": manifest_id,
            "control_turn_id": control_turn_id,
            "candidate": {"commit": "1" * 40, "tree": "2" * 40},
            "work_units": {"epic_id": bead_id, "live_work_unit_id": work_unit_id},
        }
        artifacts = {
            name: snapshot({"artifact": name})
            for name in (
                "authorization",
                "manifest",
                "authorization-state",
                "failure-evidence",
                "global-claim",
                "authorization-marker",
                "nonce-marker",
                "scope-state",
                "preflight",
                "pre-mutation-receipt",
                "pre-mutation-adjudication",
                "pre-live-receipt",
                "pre-live-adjudication",
                "allocation-ledger",
                "steering-registry",
                "containment",
                "recovery-steering-receipt",
                "authorization-recovery-cause-evidence",
                "outer-authority",
                "independent-validation-receipt",
            )
        }
        runner_source = (
            b'{"replacement_attempt_count": 0}\n'
            b"read_recovery_pending = True\n"
            b'capture_recovery_boundary("at-fault")\n'
        )
        boundary_source = (
            b"if not raw:\n"
            b'    raise ValueError("session file has no complete records")\n'
        )
        proof = CONTRACTS.Version10InterruptedEmptyBoundaryPredecessorProofInputs(
            authorization=artifacts["authorization"],
            manifest=artifacts["manifest"],
            authorization_state=artifacts["authorization-state"],
            failure_evidence=artifacts["failure-evidence"],
            global_claim=artifacts["global-claim"],
            authorization_marker=artifacts["authorization-marker"],
            nonce_marker=artifacts["nonce-marker"],
            scope_state=artifacts["scope-state"],
            preflight=artifacts["preflight"],
            pre_mutation_receipt=artifacts["pre-mutation-receipt"],
            pre_mutation_adjudication=artifacts["pre-mutation-adjudication"],
            pre_live_receipt=artifacts["pre-live-receipt"],
            pre_live_adjudication=artifacts["pre-live-adjudication"],
            allocation_ledger=artifacts["allocation-ledger"],
            allocation_audit_bytes=b'{"event":"audit"}\n',
            steering_registry=artifacts["steering-registry"],
            terminal_session_bytes=terminal_session,
            containment=artifacts["containment"],
            terminal_facts=snapshot({"placeholder": True}),
            generation11_runner_source_bytes=runner_source,
            generation11_session_boundary_source_bytes=boundary_source,
            recovery_cause_analysis_bytes=b"bounded cause analysis\n",
            recovery_steering_receipt=artifacts["recovery-steering-receipt"],
            recovery_steering_session_bytes=b'{"type":"session_meta"}\n',
            authorization_recovery_cause_evidence=artifacts[
                "authorization-recovery-cause-evidence"
            ],
            authorization_recovery_cause_source_analysis=b"source analysis\n",
            outer_authority=artifacts["outer-authority"],
            independent_validation_receipt=artifacts[
                "independent-validation-receipt"
            ],
            independent_validation_session_bytes=b'{"type":"session_meta"}\n',
            ancestor=None,  # type: ignore[arg-type]
        )
        session_records = [json.loads(line) for line in terminal_session.splitlines()]
        terminal_payload = session_records[-1]["payload"]
        expected_sources = {
            "authorization_file_sha256": proof.authorization.raw_sha256,
            "manifest_file_sha256": proof.manifest.raw_sha256,
            "authorization_state_file_sha256": proof.authorization_state.raw_sha256,
            "failure_evidence_file_sha256": proof.failure_evidence.raw_sha256,
            "containment_file_sha256": proof.containment.raw_sha256,
            "global_claim_file_sha256": proof.global_claim.raw_sha256,
            "authorization_marker_file_sha256": proof.authorization_marker.raw_sha256,
            "nonce_marker_file_sha256": proof.nonce_marker.raw_sha256,
            "scope_state_file_sha256": proof.scope_state.raw_sha256,
            "preflight_file_sha256": proof.preflight.raw_sha256,
            "pre_mutation_receipt_file_sha256": proof.pre_mutation_receipt.raw_sha256,
            "pre_mutation_adjudication_file_sha256": proof.pre_mutation_adjudication.raw_sha256,
            "pre_live_receipt_file_sha256": proof.pre_live_receipt.raw_sha256,
            "pre_live_adjudication_file_sha256": proof.pre_live_adjudication.raw_sha256,
            "allocation_ledger_file_sha256": proof.allocation_ledger.raw_sha256,
            "allocation_audit_file_sha256": hashlib.sha256(
                proof.allocation_audit_bytes
            ).hexdigest(),
            "steering_registry_file_sha256": proof.steering_registry.raw_sha256,
            "terminal_session_file_sha256": hashlib.sha256(
                proof.terminal_session_bytes
            ).hexdigest(),
            "outer_authority_file_sha256": proof.outer_authority.raw_sha256,
            "recovery_cause_analysis_sha256": hashlib.sha256(
                proof.recovery_cause_analysis_bytes
            ).hexdigest(),
            "recovery_steering_receipt_file_sha256": (
                proof.recovery_steering_receipt.raw_sha256
            ),
            "recovery_steering_session_file_sha256": hashlib.sha256(
                proof.recovery_steering_session_bytes
            ).hexdigest(),
            "generation11_runner_source_sha256": hashlib.sha256(
                runner_source
            ).hexdigest(),
            "generation11_session_boundary_source_sha256": hashlib.sha256(
                boundary_source
            ).hexdigest(),
        }
        fact_spec = {
            "initial_empty_boundary": (
                CONTRACTS.GENERATION11_INITIAL_EMPTY_BOUNDARY,
                "source-code-derived-inference",
                [
                    "generation11-runner-source",
                    "generation11-session-boundary-source",
                    "failure-evidence",
                ],
            ),
            "recovery_entry": (
                CONTRACTS.GENERATION11_RECOVERY_ENTRY,
                "source-code-derived-inference",
                ["generation11-runner-source", "failure-evidence"],
            ),
            "interrupted_terminal_event": (
                terminal_payload,
                "direct-session-telemetry",
                ["terminal-session", "allocation-ledger"],
            ),
            "no_replacement_read": (
                CONTRACTS.GENERATION11_NO_REPLACEMENT_READ,
                "source-code-derived-inference",
                [
                    "generation11-runner-source",
                    "allocation-ledger",
                    "steering-registry",
                ],
            ),
        }
        facts: dict[str, dict] = {}
        bindings = deepcopy(terminal_bindings)
        for name, (value, provenance, source_labels) in fact_spec.items():
            fact_sha256 = CONTRACTS._generation11_fact_sha256(
                value, leaf=name.replace("_", "-")
            )
            facts[name] = {
                "provenance": provenance,
                "source_labels": source_labels,
                "value": value,
                "fact_sha256": fact_sha256,
            }
            bindings[f"predecessor_{name}_sha256"] = fact_sha256
        terminal_facts = {
            "artifact_type": "cwo-generation11-terminal-facts",
            "version": 1,
            "schema": "schemas/generation11-terminal-facts.schema.json",
            "recorded_at": "2026-07-18T13:30:00Z",
            "identity": {
                "authorization_id": authorization_id,
                "manifest_id": manifest_id,
                "campaign_nonce": authorization["bindings"]["campaign_nonce"],
                "control_turn_id": control_turn_id,
                "bead_id": bead_id,
                "work_unit_id": work_unit_id,
                "live_generation": 11,
                "session_id": bindings["predecessor_terminal_session_id"],
                "turn_id": bindings["predecessor_terminal_turn_id"],
                "candidate_commit": manifest["candidate"]["commit"],
                "candidate_tree": manifest["candidate"]["tree"],
            },
            "source_bindings": expected_sources,
            "facts": facts,
            "source_root_sha256": CONTRACTS.canonical_sha256(expected_sources),
        }
        terminal_facts_snapshot = self._reseal(
            terminal_facts, "canonical_terminal_facts_sha256"
        )
        proof = replace(proof, terminal_facts=terminal_facts_snapshot)
        bindings.update(
            {
                "predecessor_terminal_facts_file_sha256": (
                    terminal_facts_snapshot.raw_sha256
                ),
                "predecessor_terminal_facts_canonical_sha256": (
                    terminal_facts_snapshot.value[
                        "canonical_terminal_facts_sha256"
                    ]
                ),
                "predecessor_generation11_runner_source_sha256": (
                    expected_sources["generation11_runner_source_sha256"]
                ),
                "predecessor_generation11_session_boundary_source_sha256": (
                    expected_sources[
                        "generation11_session_boundary_source_sha256"
                    ]
                ),
            }
        )
        failure = {
            **failure,
            "failure_message_sha256": CONTRACTS.GENERATION11_FAILURE_MESSAGE_SHA256,
        }
        return (
            proof,
            bindings,
            authorization,
            manifest,
            failure,
            (
                expected_sources["generation11_runner_source_sha256"],
                expected_sources["generation11_session_boundary_source_sha256"],
            ),
        )

    def recovery_steering_fixture(
        self,
        *,
        authorization_id: str | None = None,
        authorization_sha256: str = "a" * 64,
        bead_id: str = "complex-work-orchestration-fsh.2.6.52",
        control_turn_id: str = "generation12-control-turn",
    ) -> tuple[CONTRACTS.JsonArtifactSnapshot, bytes, dict, dict, dict, str]:
        authorization_id = authorization_id or str(uuid.uuid4())
        session_id = str(uuid.uuid4())
        submission_id = str(uuid.uuid4())
        opinion = {
            "recommendation": "conditional-go",
            "confidence": 0.94,
            "findings": [
                {"code": "EMPTY_FILE_RACE", "severity": "high"},
                {"code": "TERMINAL_LEAVES", "severity": "medium"},
                {"code": "VERSION_DISPATCH", "severity": "medium"},
                {"code": "AUTONOMY_BOUNDARY", "severity": "low"},
            ],
            "conditions": [
                "derive terminal leaves",
                "bind recovery evidence",
                "bump authority tuple",
                "require fresh generation",
            ],
        }
        session = self._recovery_session(
            opinion=opinion,
            session_id=session_id,
            submission_id=submission_id,
        )
        session_sha256 = hashlib.sha256(session).hexdigest()
        final_text = json.dumps(opinion, sort_keys=True, separators=(",", ":"))
        receipt = {
            "schema": "cwo-steering-receipt:v1",
            "gate": "recovery-steering",
            "bead_id": bead_id,
            "authorization_id": authorization_id,
            "authorization_sha256": authorization_sha256,
            "control_turn_id": control_turn_id,
            "submission_id": submission_id,
            "client_user_message_id": str(uuid.uuid4()),
            "session_id": session_id,
            "agent": "recovery-architect",
            "model": CONTRACTS.EXACT_STEERING_MODEL,
            "effort": CONTRACTS.EXACT_STEERING_EFFORT,
            "attestation_source": "initialized-codex-home-session-jsonl-turn-context",
            "model_discovery": {"source": "trusted-control-plane"},
            "input": {"share_boundary": "read-only"},
            "boundary": {
                "baseline": {
                    "record_count": 0,
                    "byte_offset": 0,
                    "boundary_sha256": hashlib.sha256(b"").hexdigest(),
                    "invalid_record_count": 0,
                    "trailing_partial": False,
                },
                "terminal": {
                    "record_count": len(session.splitlines()),
                    "byte_offset": len(session),
                    "boundary_sha256": session_sha256,
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
            "guard": {"uninterrupted": True},
            "opinion": opinion,
            "final_response_sha256": hashlib.sha256(final_text.encode()).hexdigest(),
            "started_at": "2026-07-18T13:00:00Z",
            "completed_at": "2026-07-18T13:01:00Z",
            "closure_outcome": "completed-and-archived",
            "disposition": "conditional",
        }
        receipt_snapshot = self._reseal(receipt, "canonical_receipt_sha256")
        bindings = {
            "predecessor_authorization_file_sha256": authorization_sha256,
            "predecessor_recovery_steering_receipt_file_sha256": (
                receipt_snapshot.raw_sha256
            ),
            "predecessor_recovery_steering_receipt_canonical_sha256": (
                receipt_snapshot.value["canonical_receipt_sha256"]
            ),
            "predecessor_recovery_steering_session_file_sha256": session_sha256,
        }
        authorization = {"authorization_id": authorization_id}
        manifest = {"work_units": {"live_work_unit_id": bead_id}}
        return (
            receipt_snapshot,
            session,
            bindings,
            authorization,
            manifest,
            control_turn_id,
        )

    def _recovery_session(
        self,
        *,
        opinion: dict,
        session_id: str,
        submission_id: str,
    ) -> bytes:
        final_text = json.dumps(opinion, sort_keys=True, separators=(",", ":"))
        records = [
            {"type": "session_meta", "payload": {"id": session_id}},
            {
                "type": "event_msg",
                "payload": {"type": "task_started", "turn_id": submission_id},
            },
            {
                "type": "response_item",
                "payload": {"type": "message", "role": "developer"},
            },
            {
                "type": "response_item",
                "payload": {"type": "message", "role": "developer"},
            },
            {
                "type": "response_item",
                "payload": {"type": "message", "role": "developer"},
            },
            {
                "type": "response_item",
                "payload": {"type": "message", "role": "user"},
            },
            {"type": "world_state", "payload": {}},
            {
                "type": "turn_context",
                "payload": {
                    "turn_id": submission_id,
                    "model": CONTRACTS.EXACT_STEERING_MODEL,
                    "effort": CONTRACTS.EXACT_STEERING_EFFORT,
                },
            },
            {
                "type": "response_item",
                "payload": {"type": "message", "role": "user"},
            },
            {"type": "event_msg", "payload": {"type": "user_message"}},
            {"type": "response_item", "payload": {"type": "reasoning"}},
            {"type": "response_item", "payload": {"type": "reasoning"}},
            {
                "type": "event_msg",
                "payload": {
                    "type": "agent_message",
                    "phase": "final_answer",
                    "message": final_text,
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "assistant",
                    "phase": "final_answer",
                    "content": [{"type": "output_text", "text": final_text}],
                },
            },
            {"type": "event_msg", "payload": {"type": "token_count"}},
            {
                "type": "event_msg",
                "payload": {"type": "task_complete", "turn_id": submission_id},
            },
        ]
        return self._jsonl(records)

    def _reseal_recovery_fixture(
        self,
        receipt_value: dict,
        session: bytes,
        bindings: dict,
    ) -> tuple[CONTRACTS.JsonArtifactSnapshot, dict]:
        value = deepcopy(receipt_value)
        value["boundary"]["terminal"].update(
            {
                "record_count": len(session.splitlines()),
                "byte_offset": len(session),
                "boundary_sha256": hashlib.sha256(session).hexdigest(),
            }
        )
        value["final_response_sha256"] = hashlib.sha256(
            json.dumps(value["opinion"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        receipt = self._reseal(value, "canonical_receipt_sha256")
        new_bindings = deepcopy(bindings)
        new_bindings.update(
            {
                "predecessor_recovery_steering_receipt_file_sha256": (
                    receipt.raw_sha256
                ),
                "predecessor_recovery_steering_receipt_canonical_sha256": (
                    receipt.value["canonical_receipt_sha256"]
                ),
                "predecessor_recovery_steering_session_file_sha256": hashlib.sha256(
                    session
                ).hexdigest(),
            }
        )
        return receipt, new_bindings

    def steering_adjudication_fixture(self, gate: str = "pre-live") -> tuple[
        CONTRACTS.JsonArtifactSnapshot, dict, dict, CONTRACTS.JsonArtifactSnapshot
    ]:
        bead_id = "complex-work-orchestration-fsh.2.6.49"
        authorization_id = str(uuid.uuid4())
        control_turn_id = str(uuid.uuid4())
        receipt = snapshot(
            {
                "bead_id": bead_id,
                "control_turn_id": control_turn_id,
                "authorization_sha256": "1" * 64,
                "canonical_receipt_sha256": "2" * 64,
                "session_id": str(uuid.uuid4()),
                "boundary": {"terminal": {"boundary_sha256": "5" * 64}},
                "opinion": {
                    "recommendation": "go",
                    "confidence": 0.91,
                    "conditions": [],
                },
            }
        )
        authorization = {
            "authorization_id": authorization_id,
            "scope": {"ordered_work_units": [bead_id]},
        }
        manifest = {"candidate": {"commit": "3" * 40, "tree": "4" * 40}}
        adjudication = {
            "adjudication_type": "cwo-main-architect-inner-steering-adjudication:v1",
            "recorded_at": "2026-07-18T12:00:00Z",
            "bead_id": bead_id,
            "control_turn_id": control_turn_id,
            "gate": gate,
            "authorization_id": authorization_id,
            "authorization_file_sha256": "1" * 64,
            "candidate_commit": manifest["candidate"]["commit"],
            "candidate_tree": manifest["candidate"]["tree"],
            "sol_receipt_file_sha256": receipt.raw_sha256,
            "sol_receipt_canonical_sha256": "2" * 64,
            "sol_session_file_sha256": "5" * 64,
            "sol_session_id": receipt.value["session_id"],
            "sol_recommendation": "go",
            "sol_confidence": 0.91,
            "opus_evidence_file_sha256": "6" * 64,
            "opus_adjudication_file_sha256": "7" * 64,
            "spark_validation_receipt_file_sha256": "8" * 64,
            "spark_validation_receipt_canonical_sha256": "9" * 64,
            "main_architect_decision": "go",
            "main_confidence": 0.95,
            "combined_confidence": 0.91,
            "combined_confidence_formula": "min(main,sol)",
            "condition_adjudication": [],
            "unresolved_high_findings": [],
            "unresolved_medium_findings": [],
            "zero_allocation_preflight_required": True,
            "manifest_authorized": True,
            "live_campaign_authorized": gate == "pre-live",
            "live_campaign_single_shot": True,
            "live_campaign_start_count_exact": 7,
            "release_authorized": False,
            "publication_authorized": False,
            "glm52": "forbidden",
            "synthesis": "forbidden",
        }
        return (
            self._reseal(adjudication, "canonical_adjudication_sha256"),
            authorization,
            manifest,
            receipt,
        )

    def containment_fixture(self) -> tuple[
        CONTRACTS.JsonArtifactSnapshot,
        dict,
        dict,
        dict,
        dict,
        CONTRACTS.Version10InterruptedEmptyBoundaryPredecessorProofInputs,
        dict,
        dict,
    ]:
        proof, bindings, authorization, manifest, _failure, _source_hashes = (
            self.terminal_facts_fixture()
        )
        authorization = deepcopy(authorization)
        manifest = deepcopy(manifest)
        outer_authority_id = str(uuid.uuid4())
        authorization["run_generation"] = 23
        authorization["bindings"].update(
            {
                "origin_main_commit": "3" * 40,
                "guarded_primary_diff_sha256": "4" * 64,
                "outer_authority_id": outer_authority_id,
            }
        )
        manifest["candidate"] = {"commit": "5" * 40, "tree": "6" * 40}
        authorization_state = snapshot(
            {"state": "contained", "state_sha256": "7" * 64}
        )
        global_claim = snapshot(
            {
                "canonical_claim_sha256": "8" * 64,
                "launch_claim_sha256": "9" * 64,
            }
        )
        authorization_marker = snapshot({"canonical_marker_sha256": "a" * 64})
        nonce_marker = snapshot({"canonical_marker_sha256": "b" * 64})
        scope_state = snapshot(
            {
                "scope_key": "scope-generation11",
                "phase": "terminal-contained",
                "canonical_state_sha256": "c" * 64,
            }
        )
        preflight = snapshot({"canonical_preflight_sha256": "d" * 64})
        pre_mutation_receipt = snapshot(
            {
                "canonical_receipt_sha256": "e" * 64,
                "authorization_id": authorization["authorization_id"],
                "submission_id": str(uuid.uuid4()),
                "gate": "pre-mutation",
            }
        )
        pre_live_receipt = snapshot(
            {
                "canonical_receipt_sha256": "f" * 64,
                "authorization_id": authorization["authorization_id"],
                "submission_id": str(uuid.uuid4()),
                "gate": "pre-live",
            }
        )
        pre_mutation_adjudication = snapshot(
            {"canonical_adjudication_sha256": "0" * 64}
        )
        pre_live_adjudication = snapshot(
            {"canonical_adjudication_sha256": "1" * 64}
        )
        steering_registry = snapshot(
            {
                "consumed": [
                    {"phase_nonce": str(uuid.uuid4())},
                    {"phase_nonce": str(uuid.uuid4())},
                ]
            }
        )
        terminal_records_for_ledger = [
            json.loads(line) for line in proof.terminal_session_bytes.splitlines()
        ]
        terminal_session_id = terminal_records_for_ledger[0]["payload"]["id"]
        terminal_turn_id = terminal_records_for_ledger[1]["payload"]["turn_id"]
        ledger_entries = [
            {"event": "allocation-intent"},
            {"event": "thread-bound", "thread_id": terminal_session_id},
            {"event": "turn-intent"},
            {
                "event": "turn-bound",
                "thread_id": terminal_session_id,
                "turn_id": terminal_turn_id,
            },
            {"event": "interrupt-observed"},
            {"event": "archive-observed"},
            {"event": "containment-audited"},
        ]
        allocation_ledger = snapshot(
            {
                "entries": ledger_entries,
                "head_entry_sha256": "2" * 64,
                "ledger_id": str(uuid.uuid4()),
                "sequence": len(ledger_entries),
                "state_sha256": "3" * 64,
            }
        )
        allocation_audit_bytes = self._jsonl(
            [{"event": "allocation-intent"}, {"event": "containment-audited"}]
        )
        outer_authority = snapshot(
            {
                "authority_id": outer_authority_id,
                "canonical_outer_authority_sha256": "4" * 64,
            }
        )
        authorization["bindings"].update(
            {
                "outer_authority_file_sha256": outer_authority.raw_sha256,
                "outer_authority_canonical_sha256": "4" * 64,
            }
        )
        (
            recovery_receipt,
            recovery_session,
            _recovery_bindings,
            _recovery_authorization,
            _recovery_manifest,
            _recovery_control_turn,
        ) = self.recovery_steering_fixture(
            authorization_id=authorization["authorization_id"],
            authorization_sha256=proof.authorization.raw_sha256,
            bead_id=manifest["work_units"]["live_work_unit_id"],
            control_turn_id=manifest["control_turn_id"],
        )
        recovery_cause_analysis = b"bounded generation12 recovery cause analysis\n"
        proof = replace(
            proof,
            authorization_state=authorization_state,
            global_claim=global_claim,
            authorization_marker=authorization_marker,
            nonce_marker=nonce_marker,
            scope_state=scope_state,
            preflight=preflight,
            pre_mutation_receipt=pre_mutation_receipt,
            pre_mutation_adjudication=pre_mutation_adjudication,
            pre_live_receipt=pre_live_receipt,
            pre_live_adjudication=pre_live_adjudication,
            allocation_ledger=allocation_ledger,
            allocation_audit_bytes=allocation_audit_bytes,
            steering_registry=steering_registry,
            recovery_cause_analysis_bytes=recovery_cause_analysis,
            recovery_steering_receipt=recovery_receipt,
            recovery_steering_session_bytes=recovery_session,
            outer_authority=outer_authority,
        )
        terminal_records = [
            json.loads(line) for line in proof.terminal_session_bytes.splitlines()
        ]
        session_id = terminal_records[0]["payload"]["id"]
        turn_id = terminal_records[1]["payload"]["turn_id"]
        contained_session = {
            "active_match_count": 0,
            "archive_match_count": 1,
            "assistant_messages": 0,
            "attested_effort": CONTRACTS.EXACT_OPERATIVE_EFFORT,
            "attested_model": CONTRACTS.EXACT_OPERATIVE_MODEL,
            "byte_offset": len(proof.terminal_session_bytes),
            "compactions": 0,
            "custom_tool_calls": 0,
            "file_sha256": hashlib.sha256(
                proof.terminal_session_bytes
            ).hexdigest(),
            "function_calls": 0,
            "patch_events": 0,
            "record_count": len(terminal_records),
            "reroutes": 0,
            "session_id": session_id,
            "store": "archived_sessions",
            "terminal_event": {
                "count": 1,
                "event_type": "turn_aborted",
                "record_index": len(terminal_records) - 1,
                "status": "interrupted",
            },
            "trusted_turn_context_count": 1,
            "turn_context_record_index": 5,
            "turn_id": turn_id,
            "workspace_mutation_evidence": "zero-tool-plus-stable-checkout-guards",
        }
        ledger_summary = {
            "unresolved_allocation_intent_count": 0,
            "unresolved_turn_intent_count": 0,
        }
        expected_containment = {
            "all_allocations_contained": True,
            "active_sessions": 0,
            "workspace_mutations_observed": 0,
        }
        failure = {
            "failure_message_sha256": CONTRACTS.GENERATION11_FAILURE_MESSAGE_SHA256,
            "evidence_sha256": "5" * 64,
            "containment": expected_containment,
        }
        expected_allocation = {
            "audit_anchor_count": 2,
            "audit_chain_valid": True,
            "audit_file_sha256": hashlib.sha256(allocation_audit_bytes).hexdigest(),
            "exact_lifecycle": [item["event"] for item in ledger_entries],
            "head_entry_sha256": allocation_ledger.value["head_entry_sha256"],
            "ledger_file_sha256": allocation_ledger.raw_sha256,
            "ledger_id": allocation_ledger.value["ledger_id"],
            "sequence": allocation_ledger.value["sequence"],
            "state_sha256": allocation_ledger.value["state_sha256"],
            "unresolved_allocation_intents": 0,
            "unresolved_turn_intents": 0,
        }
        expected_claim_scope = {
            "authorization_marker_canonical_sha256": "a" * 64,
            "authorization_marker_file_sha256": authorization_marker.raw_sha256,
            "authorization_state": "contained",
            "authorization_state_canonical_sha256": "7" * 64,
            "authorization_state_file_sha256": authorization_state.raw_sha256,
            "global_claim_canonical_sha256": "8" * 64,
            "global_claim_file_sha256": global_claim.raw_sha256,
            "launch_claim_sha256": "9" * 64,
            "launch_claim_version": 5,
            "nonce_marker_canonical_sha256": "b" * 64,
            "nonce_marker_file_sha256": nonce_marker.raw_sha256,
            "preflight_canonical_sha256": "d" * 64,
            "preflight_file_sha256": preflight.raw_sha256,
            "scope_key": "scope-generation11",
            "scope_phase": "terminal-contained",
            "scope_snapshot_basename": "generation11-contained-scope-state-v32.json",
            "scope_snapshot_canonical_sha256": "c" * 64,
            "scope_snapshot_file_sha256": scope_state.raw_sha256,
            "scope_state_canonical_sha256": "c" * 64,
            "scope_state_file_sha256": scope_state.raw_sha256,
            "terminal_evidence_canonical_sha256": "5" * 64,
            "tombstones_permanent": True,
        }
        expected_steering: dict[str, dict] = {}
        for phase, receipt, adjudication, consumption in (
            (
                "pre-mutation",
                pre_mutation_receipt,
                pre_mutation_adjudication,
                steering_registry.value["consumed"][0],
            ),
            (
                "pre-live",
                pre_live_receipt,
                pre_live_adjudication,
                steering_registry.value["consumed"][1],
            ),
        ):
            expected_steering[phase] = {
                "adjudication_file_sha256": adjudication.raw_sha256,
                "consumed_exactly_once": True,
                "consumption_sha256": CONTRACTS._domain_sha256(
                    {
                        "receipt": receipt.value["canonical_receipt_sha256"],
                        "run": receipt.value["authorization_id"],
                        "attempt": receipt.value["submission_id"],
                        "gate": receipt.value["gate"],
                        "phase_nonce": consumption["phase_nonce"],
                        "adjudication": adjudication.raw_sha256,
                    },
                    domain="steering-receipt-consumption",
                ),
                "phase_nonce": consumption["phase_nonce"],
                "receipt_canonical_sha256": receipt.value[
                    "canonical_receipt_sha256"
                ],
                "receipt_file_sha256": receipt.raw_sha256,
            }
        recovery_records = [json.loads(line) for line in recovery_session.splitlines()]
        recovery_sha256 = hashlib.sha256(recovery_session).hexdigest()
        recovery_sol_session = {
            "archived": True,
            "attested_effort": CONTRACTS.EXACT_STEERING_EFFORT,
            "attested_model": CONTRACTS.EXACT_STEERING_MODEL,
            "boundary_sha256": recovery_sha256,
            "byte_offset": len(recovery_session),
            "compactions": 0,
            "custom_tool_calls": 0,
            "file_sha256": recovery_sha256,
            "function_calls": 0,
            "record_count": len(recovery_records),
            "reroutes": 0,
            "session_id": recovery_receipt.value["session_id"],
            "terminal_event": {
                "count": 1,
                "event_type": "task_complete",
                "record_index": len(recovery_records) - 1,
                "status": "completed",
            },
            "turn_id": recovery_records[1]["payload"]["turn_id"],
        }
        recovery_contract = {
            "accepted_finding_codes": [
                "EMPTY_FILE_RACE",
                "TERMINAL_LEAVES",
                "VERSION_DISPATCH",
                "AUTONOMY_BOUNDARY",
            ],
            "cause_analysis_file_sha256": hashlib.sha256(
                recovery_cause_analysis
            ).hexdigest(),
            "fresh_authority_required": True,
            "implementation_conditions_are_mandatory": True,
            "live_launch_authorized_by_this_artifact": False,
            "required_authorization_version": 11,
            "required_launch_claim_version": 6,
            "required_manifest_version": 8,
            "required_validator_version": 6,
            "sol_confidence": 0.94,
            "sol_receipt_canonical_sha256": recovery_receipt.value[
                "canonical_receipt_sha256"
            ],
            "sol_receipt_file_sha256": recovery_receipt.raw_sha256,
            "sol_recommendation": "conditional-go",
            "sol_session": recovery_sol_session,
        }
        control_recheck = {
            "cap_two_operative_release": False,
            "current_successor_implementation_in_progress": True,
            "failure_time_tracked_clean": True,
            "isolated_checkout_head": manifest["candidate"]["commit"],
            "isolated_checkout_tree": manifest["candidate"]["tree"],
            "native_supervision_pool_status": "canary-gated",
            "operative_dispatch_authorized": False,
            "origin_main_commit": authorization["bindings"]["origin_main_commit"],
            "protected_primary_diff_sha256": authorization["bindings"][
                "guarded_primary_diff_sha256"
            ],
            "release_gate_passed": False,
            "transient_successor_worktree_diff_bound": False,
            "workspace_mutations_observed": 0,
        }
        bindings.update(
            {
                "predecessor_authorization_file_sha256": proof.authorization.raw_sha256,
                "predecessor_authorization_canonical_sha256": "6" * 64,
                "predecessor_manifest_file_sha256": proof.manifest.raw_sha256,
                "predecessor_manifest_canonical_sha256": "7" * 64,
                "predecessor_failure_evidence_file_sha256": proof.failure_evidence.raw_sha256,
                "predecessor_failure_evidence_canonical_sha256": "5" * 64,
            }
        )
        containment = {
            "allocation_ledger": expected_allocation,
            "bead_id": manifest["work_units"]["live_work_unit_id"],
            "claim_v5_and_scope": expected_claim_scope,
            "contained_session": contained_session,
            "containment": expected_containment,
            "control_plane_recheck": control_recheck,
            "control_turn_id": manifest["control_turn_id"],
            "disposition": {
                "authorization_state": "containment-only",
                "generation11_retry_resume_substitute_bridge_salvage": False,
                "generation11_state": "terminal-contained",
                "glm_5_2_used": False,
                "model_synthesis_used": False,
                "operative_dispatch_authorized": False,
                "publish_push_install_authorized": False,
                "release_gate_passed": False,
                "requires_fresh_live_generation": 12,
            },
            "failed_authority": {
                "authorization_canonical_sha256": "6" * 64,
                "authorization_file_sha256": proof.authorization.raw_sha256,
                "authorization_id": authorization["authorization_id"],
                "authorization_version": 10,
                "campaign_nonce": authorization["bindings"]["campaign_nonce"],
                "live_generation": 11,
                "manifest_canonical_sha256": "7" * 64,
                "manifest_file_sha256": proof.manifest.raw_sha256,
                "manifest_id": manifest["manifest_id"],
                "manifest_version": 7,
                "outer_authority_canonical_sha256": "4" * 64,
                "outer_authority_file_sha256": outer_authority.raw_sha256,
                "outer_authority_id": outer_authority_id,
                "run_generation": 23,
            },
            "generation12_recovery_contract": recovery_contract,
            "recorded_at": "2026-07-18T14:00:00Z",
            "root_cause": {
                "cause_class": "empty-materialized-session-boundary-rejected",
                "existing_zero_byte_session_boundary_accepted": False,
                "failed_edge": "capability-read-recovery:at-fault",
                "independently_reproduced_failure_message_hash": True,
                "missing_session_boundary_accepted": True,
                "replacement_read_attempted": False,
                "source_analysis_file_sha256": hashlib.sha256(
                    recovery_cause_analysis
                ).hexdigest(),
            },
            "schema": "cwo-live-campaign-containment-recovery:v5",
            "steering_consumptions": expected_steering,
            "terminal_failure": {
                "failure_class": "AppServerError",
                "failure_code": "AppServerError",
                "failure_evidence_canonical_sha256": "5" * 64,
                "failure_evidence_file_sha256": proof.failure_evidence.raw_sha256,
                "failure_message": "capability-read-recovery-fault-boundary-invalid:session file has no complete records",
                "failure_message_sha256": CONTRACTS.GENERATION11_FAILURE_MESSAGE_SHA256,
                "first_protected_fault": None,
                "validation_outcome": "rejected",
            },
            "version": 5,
        }
        containment_snapshot = self._reseal(
            containment, "canonical_recovery_sha256"
        )
        proof = replace(proof, containment=containment_snapshot)
        bindings.update(
            {
                "predecessor_containment_file_sha256": containment_snapshot.raw_sha256,
                "predecessor_containment_canonical_sha256": (
                    containment_snapshot.value["canonical_recovery_sha256"]
                ),
            }
        )
        return (
            containment_snapshot,
            bindings,
            authorization,
            manifest,
            failure,
            proof,
            ledger_summary,
            expected_containment,
        )

    def test_v11_v8_schemas_match_strict_runtime_sets(self) -> None:
        authorization = json.loads(
            (ROOT / CONTRACTS.AUTHORIZATION_SCHEMA_V11).read_text(encoding="utf-8")
        )
        manifest = json.loads(
            (ROOT / CONTRACTS.MANIFEST_SCHEMA_V8).read_text(encoding="utf-8")
        )
        self.assertFalse(authorization["additionalProperties"])
        self.assertFalse(manifest["additionalProperties"])
        self.assertEqual(
            set(authorization["$defs"]["bindings"]["required"]),
            CONTRACTS.BINDING_FIELDS_V11,
        )
        self.assertEqual(
            set(manifest["$defs"]["predecessor"]["required"]),
            CONTRACTS.MANIFEST_PREDECESSOR_FIELDS_V8,
        )

    def test_only_v11_v8_v6_v6_is_operative(self) -> None:
        self.assertEqual(
            CONTRACTS.validate_operative_version_tuple(11, 8, 6, 6), []
        )
        for observed in ((10, 7, 5, 5), (11, 7, 6, 6), (11, 8, 5, 6)):
            with self.subTest(observed=observed):
                self.assertEqual(
                    CONTRACTS.validate_operative_version_tuple(*observed),
                    ["operative-version-tuple-incompatible"],
                )
        self.assertEqual(
            CONTRACTS.validate_operative_version_tuple(11, 8, "6", 6),
            ["operative-version-tuple-malformed"],
        )

    def test_v11_common_shadow_projects_only_legacy_allowed_actions(self) -> None:
        supersession = {
            "prior_authorization_id": str(uuid.uuid4()),
            "prior_terminal_state": "containment-only",
            "prior_live_generation": 11,
            "prior_allocations": 1,
            "prior_ambiguities": 0,
            "prior_allowed_actions": 8,
            "reuse_resume_retry_substitution_salvage_bridge": False,
        }
        authorization = {
            "version": CONTRACTS.AUTHORIZATION_VERSION_V11,
            "schema": CONTRACTS.AUTHORIZATION_SCHEMA_V11,
            "bindings": {},
            "mandatory_gates": {},
            "progress_gate": {},
            "supersession": supersession,
        }
        original = deepcopy(authorization)

        shadow = CONTRACTS._v11_common_shadow(authorization)

        self.assertEqual(authorization, original)
        self.assertEqual(authorization["supersession"]["prior_allowed_actions"], 8)
        self.assertEqual(shadow["supersession"]["prior_allowed_actions"], 0)
        expected_shadow_supersession = deepcopy(supersession)
        expected_shadow_supersession["prior_allowed_actions"] = 0
        self.assertEqual(shadow["supersession"], expected_shadow_supersession)

    def test_v8_manifest_shadow_projects_only_legacy_ledger_aliases(self) -> None:
        actual = {
            "allocation_ledger_file_sha256": "1" * 64,
            "allocation_ledger_state_sha256": "2" * 64,
            "allocation_audit_file_sha256": "3" * 64,
        }
        aliases = {
            "predecessor_global_claim_file_sha256": "4" * 64,
            "predecessor_scope_state_canonical_sha256": "5" * 64,
            "predecessor_authorization_marker_file_sha256": "6" * 64,
        }
        authorization = {
            "version": CONTRACTS.AUTHORIZATION_VERSION_V11,
            "schema": CONTRACTS.AUTHORIZATION_SCHEMA_V11,
            "bindings": {
                **aliases,
                **{
                    f"predecessor_{field}": value
                    for field, value in actual.items()
                },
            },
            "mandatory_gates": {},
            "progress_gate": {},
            "supersession": {"prior_allowed_actions": 8},
        }
        predecessor = {
            "authorization_file_sha256": "7" * 64,
            "recovery_cause_evidence_file_sha256": "8" * 64,
            "recovery_cause_evidence_canonical_sha256": "9" * 64,
            "ancestor_lineage_sha256": "a" * 64,
            "validator_contract_sha256": "b" * 64,
            **actual,
        }
        manifest = {
            "version": CONTRACTS.MANIFEST_VERSION_V8,
            "schema": CONTRACTS.MANIFEST_SCHEMA_V8,
            "predecessor": predecessor,
        }
        original_authorization = deepcopy(authorization)
        original_manifest = deepcopy(manifest)

        shadow, shadow_authorization, _raw_sha256 = (
            CONTRACTS._v8_manifest_common_shadow(manifest, authorization)
        )

        self.assertEqual(authorization, original_authorization)
        self.assertEqual(manifest, original_manifest)
        shadow_predecessor = shadow["predecessor"]
        self.assertEqual(
            shadow_predecessor["allocation_ledger_file_sha256"],
            aliases["predecessor_global_claim_file_sha256"],
        )
        self.assertEqual(
            shadow_predecessor["allocation_ledger_state_sha256"],
            aliases["predecessor_scope_state_canonical_sha256"],
        )
        self.assertEqual(
            shadow_predecessor["allocation_audit_file_sha256"],
            aliases["predecessor_authorization_marker_file_sha256"],
        )
        self.assertEqual(
            shadow_predecessor["authorization_file_sha256"], "7" * 64
        )
        self.assertEqual(
            shadow_predecessor["original_containment_file_sha256"], "8" * 64
        )
        self.assertEqual(
            shadow_predecessor["original_containment_canonical_sha256"],
            "9" * 64,
        )
        self.assertNotIn("ancestor_lineage_sha256", shadow_predecessor)
        self.assertNotIn("validator_contract_sha256", shadow_predecessor)
        self.assertEqual(
            shadow_authorization["bindings"][
                "predecessor_allocation_ledger_file_sha256"
            ],
            aliases["predecessor_global_claim_file_sha256"],
        )

    def test_v8_semantics_still_reject_real_ledger_tampering(self) -> None:
        authorization_id = str(uuid.uuid4())
        bindings = {
            field: "1" * 64 for field in CONTRACTS.BINDING_FIELDS_V11
        }
        bindings.update(
            {
                "campaign_nonce": str(uuid.uuid4()),
                "checkpoint_commit": "2" * 40,
                "checkpoint_tree": "3" * 40,
                "origin_main_commit": "4" * 40,
                "pickup_path": "pickup.md",
                "recovery_plan_path": "plan.md",
                "predecessor_authorization_id": authorization_id,
                "predecessor_terminal_session_id": str(uuid.uuid4()),
                "predecessor_terminal_turn_id": str(uuid.uuid4()),
                "backup_ref": "refs/heads/backup/test",
                "outer_authority_id": str(uuid.uuid4()),
            }
        )
        progress = {
            "predecessor_candidate_commit": "5" * 40,
            "predecessor_candidate_tree": "6" * 40,
            "predecessor_lineage_sha256": "7" * 64,
            "qualification_sha256": "8" * 64,
        }
        predecessor = {
            "authorization_id": bindings["predecessor_authorization_id"],
            "authorization_file_sha256": bindings[
                "predecessor_authorization_file_sha256"
            ],
            "authorization_canonical_sha256": bindings[
                "predecessor_authorization_canonical_sha256"
            ],
            "manifest_file_sha256": bindings[
                "predecessor_manifest_file_sha256"
            ],
            "manifest_canonical_sha256": bindings[
                "predecessor_manifest_canonical_sha256"
            ],
            "authorization_state_file_sha256": bindings[
                "predecessor_authorization_state_file_sha256"
            ],
            "authorization_state_canonical_sha256": bindings[
                "predecessor_authorization_state_canonical_sha256"
            ],
            "candidate_commit": progress["predecessor_candidate_commit"],
            "candidate_tree": progress["predecessor_candidate_tree"],
            "lineage_sha256": progress["predecessor_lineage_sha256"],
            "failure_evidence_file_sha256": bindings[
                "predecessor_failure_evidence_file_sha256"
            ],
            "failure_evidence_canonical_sha256": bindings[
                "predecessor_failure_evidence_canonical_sha256"
            ],
            "containment_file_sha256": bindings[
                "predecessor_containment_file_sha256"
            ],
            "containment_canonical_sha256": bindings[
                "predecessor_containment_canonical_sha256"
            ],
            "recovery_cause_evidence_file_sha256": bindings[
                "recovery_cause_evidence_file_sha256"
            ],
            "recovery_cause_evidence_canonical_sha256": bindings[
                "recovery_cause_evidence_canonical_sha256"
            ],
            "ancestor_lineage_sha256": bindings[
                "predecessor_ancestor_lineage_sha256"
            ],
            "validator_contract_sha256": bindings[
                "validator_contract_sha256"
            ],
            "allocation_ledger_file_sha256": bindings[
                "predecessor_allocation_ledger_file_sha256"
            ],
            "allocation_ledger_state_sha256": bindings[
                "predecessor_allocation_ledger_state_sha256"
            ],
            "allocation_audit_file_sha256": bindings[
                "predecessor_allocation_audit_file_sha256"
            ],
            **{
                field.removeprefix("predecessor_"): bindings[field]
                for field in CONTRACTS.BINDING_FIELDS_V11
                - CONTRACTS.BINDING_FIELDS_V7
            },
        }
        self.assertEqual(
            set(predecessor), CONTRACTS.MANIFEST_PREDECESSOR_FIELDS_V8
        )
        authorization = {
            "version": 11,
            "authorization_id": authorization_id,
            "canonical_authorization_sha256": "9" * 64,
            "bindings": bindings,
            "progress_gate": progress,
            "mandatory_gates": {},
            "supersession": {"prior_allowed_actions": 8},
        }
        raw_sha256 = "a" * 64
        work_units = {
            "epic_id": "complex-work-orchestration-18w",
            "parent_work_unit_id": "complex-work-orchestration-18w.6",
            "live_work_unit_id": "complex-work-orchestration-18w.6.52",
        }
        manifest = {
            "manifest_type": CONTRACTS.MANIFEST_TYPE,
            "version": CONTRACTS.MANIFEST_VERSION_V8,
            "schema": CONTRACTS.MANIFEST_SCHEMA_V8,
            "authorization_id": authorization_id,
            "authorization_raw_sha256": raw_sha256,
            "authorization_canonical_sha256": authorization[
                "canonical_authorization_sha256"
            ],
            "progress_qualification_sha256": progress[
                "qualification_sha256"
            ],
            "work_units": work_units,
            "predecessor": predecessor,
        }
        manifest["manifest_sha256"] = CONTRACTS.canonical_sha256(manifest)
        outer = {
            "active_registry": {
                "contract": "cwo-active-outer-authority-registry:v1",
                "scope_key": CONTRACTS.active_outer_authority_scope_key(
                    work_units["epic_id"], work_units["parent_work_unit_id"]
                ),
            }
        }

        def validate(value: dict) -> list[str]:
            with (
                patch.object(
                    CONTRACTS,
                    "_strict",
                    side_effect=lambda item, _fields, _label, _errors: (
                        dict(item) if isinstance(item, dict) else {}
                    ),
                ),
                patch.object(
                    CONTRACTS, "_validate_campaign_manifest_v2", return_value=[]
                ),
                patch.object(
                    CONTRACTS,
                    "_validate_full_auto_authorization_v11",
                    return_value=[],
                ),
            ):
                return CONTRACTS._validate_campaign_manifest_v8(
                    value,
                    authorization=authorization,
                    authorization_raw_sha256=raw_sha256,
                    outer_authority=outer,
                    outer_authority_raw_sha256="b" * 64,
                    predecessor_proof=None,
                    recovery_cause_evidence=None,
                    recovery_cause_source_analysis=None,
                    independent_validation_receipt=None,
                    independent_validation_receipt_raw_sha256=None,
                    expected_validator_contract_sha256=None,
                    repo_root=None,
                    expected_primary_diff_sha256=None,
                )

        self.assertEqual(validate(manifest), [])
        tampered = deepcopy(manifest)
        tampered["predecessor"]["allocation_ledger_file_sha256"] = "f" * 64
        tampered.pop("manifest_sha256")
        tampered["manifest_sha256"] = CONTRACTS.canonical_sha256(tampered)
        self.assertIn(
            "campaign-manifest-v8-predecessor-authorization-mismatch",
            validate(tampered),
        )

    def test_malformed_v11_v8_inputs_fail_closed(self) -> None:
        for malformed in ({}, [], "11", True, None):
            with self.subTest(authorization=malformed):
                self.assertTrue(CONTRACTS.validate_full_auto_authorization(malformed))
            with self.subTest(manifest=malformed):
                self.assertTrue(CONTRACTS.validate_campaign_manifest(malformed))
        self.assertIn(
            "authorization-v11-bindings-not-object",
            CONTRACTS.validate_full_auto_authorization(
                {"version": 11, "bindings": "wrong-type"}
            ),
        )
        self.assertTrue(
            CONTRACTS.validate_campaign_manifest(
                {"version": 8, "predecessor": "wrong-type"},
                authorization={"version": 11},
            )
        )
        self.assertIn(
            "authorization-v11-common:authorization-v11-common-scalar-invalid",
            CONTRACTS.validate_full_auto_authorization(
                {"version": 11, "authorization_id": []}
            ),
        )
        self.assertIn(
            "campaign-manifest-v8-common:campaign-manifest-v8-common-scalar-invalid",
            CONTRACTS.validate_campaign_manifest(
                {
                    "version": 8,
                    "manifest_type": CONTRACTS.MANIFEST_TYPE,
                    "schema": CONTRACTS.MANIFEST_SCHEMA_V8,
                    "authorization_id": [],
                },
                authorization={"version": 11, "authorization_id": []},
            ),
        )

    def test_terminal_session_binds_exact_zero_activity_interrupt(self) -> None:
        fixture = self.terminal_fixture()
        containment, bindings, _authorization, _manifest, _failure, session, ledger = fixture
        self.assertEqual(
            CONTRACTS._validate_generation11_terminal_session(
                session,
                ledger=ledger,
                facts=containment.value["contained_session"],
                expected_file_sha256=bindings[
                    "predecessor_terminal_session_file_sha256"
                ],
                expected_event_sha256=bindings[
                    "predecessor_interrupted_terminal_event_sha256"
                ],
            ),
            [],
        )

    def test_terminal_session_rejects_activity_and_identity_replay(self) -> None:
        fixture = self.terminal_fixture()
        containment, bindings, _authorization, _manifest, _failure, session, ledger = fixture
        records = [json.loads(line) for line in session.splitlines()]
        records.insert(
            -1,
            {
                "type": "response_item",
                "payload": {"type": "message", "role": "assistant"},
            },
        )
        injected_session = b"".join(
            (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
            for record in records
        )
        injected_facts = deepcopy(containment.value["contained_session"])
        injected_facts.update(
            {
                "assistant_messages": 1,
                "byte_offset": len(injected_session),
                "file_sha256": hashlib.sha256(injected_session).hexdigest(),
                "record_count": len(records),
                "terminal_event": {
                    "count": 1,
                    "event_type": "turn_aborted",
                    "record_index": len(records) - 1,
                    "status": "interrupted",
                },
            }
        )
        self.assertIn(
            "authorization-predecessor-v10-terminal-session-activity-invalid",
            CONTRACTS._validate_generation11_terminal_session(
                injected_session,
                ledger=ledger,
                facts=injected_facts,
                expected_file_sha256=hashlib.sha256(injected_session).hexdigest(),
                expected_event_sha256=bindings[
                    "predecessor_interrupted_terminal_event_sha256"
                ],
            ),
        )
        replayed_facts = deepcopy(containment.value["contained_session"])
        replayed_facts["session_id"] = str(uuid.uuid4())
        self.assertIn(
            "authorization-predecessor-v10-terminal-session-binding-invalid",
            CONTRACTS._validate_generation11_terminal_session(
                session,
                ledger=ledger,
                facts=replayed_facts,
                expected_file_sha256=bindings[
                    "predecessor_terminal_session_file_sha256"
                ],
                expected_event_sha256=bindings[
                    "predecessor_interrupted_terminal_event_sha256"
                ],
            ),
        )

    def test_terminal_facts_bind_provenance_sources_and_frozen_source_bytes(self) -> None:
        proof, bindings, authorization, manifest, failure, source_hashes = (
            self.terminal_facts_fixture()
        )
        with (
            patch.object(
                CONTRACTS, "GENERATION11_RUNNER_SOURCE_SHA256", source_hashes[0]
            ),
            patch.object(
                CONTRACTS,
                "GENERATION11_SESSION_BOUNDARY_SOURCE_SHA256",
                source_hashes[1],
            ),
        ):
            self.assertEqual(
                CONTRACTS._validate_generation11_terminal_facts(
                    proof.terminal_facts,
                    bindings=bindings,
                    proof=proof,
                    authorization=authorization,
                    manifest=manifest,
                    failure=failure,
                    repo_root=None,
                ),
                [],
            )

    def test_terminal_facts_reject_resealed_unknown_provenance_and_source_changes(
        self,
    ) -> None:
        proof, bindings, authorization, manifest, failure, source_hashes = (
            self.terminal_facts_fixture()
        )
        mutations = (
            (
                "unknown-root-field",
                lambda value: value.update({"unexpected": True}),
                "authorization-predecessor-v10-terminal-facts-fields-invalid",
            ),
            (
                "provenance",
                lambda value: value["facts"]["interrupted_terminal_event"].update(
                    {"provenance": "operator-assertion"}
                ),
                "authorization-predecessor-v10-terminal-fact-interrupted_terminal_event-binding-invalid",
            ),
            (
                "source-binding",
                lambda value: value["source_bindings"].update(
                    {"global_claim_file_sha256": "f" * 64}
                ),
                "authorization-predecessor-v10-terminal-facts-binding-invalid",
            ),
            (
                "source-bytes",
                lambda _value: None,
                "authorization-predecessor-v10-terminal-facts-source-semantics-invalid",
            ),
        )
        for label, mutate, expected in mutations:
            with self.subTest(label=label):
                value = deepcopy(proof.terminal_facts.value)
                mutate(value)
                if label == "source-binding":
                    value["source_root_sha256"] = CONTRACTS.canonical_sha256(
                        value["source_bindings"]
                    )
                mutated_snapshot = self._reseal(
                    value, "canonical_terminal_facts_sha256"
                )
                mutated_proof = replace(proof, terminal_facts=mutated_snapshot)
                if label == "source-bytes":
                    mutated_proof = replace(
                        mutated_proof,
                        generation11_runner_source_bytes=b"semantics removed\n",
                    )
                mutated_bindings = deepcopy(bindings)
                mutated_bindings.update(
                    {
                        "predecessor_terminal_facts_file_sha256": (
                            mutated_snapshot.raw_sha256
                        ),
                        "predecessor_terminal_facts_canonical_sha256": (
                            mutated_snapshot.value[
                                "canonical_terminal_facts_sha256"
                            ]
                        ),
                    }
                )
                if label == "source-bytes":
                    changed_source_sha256 = hashlib.sha256(
                        mutated_proof.generation11_runner_source_bytes
                    ).hexdigest()
                    mutated_snapshot_value = deepcopy(mutated_snapshot.value)
                    mutated_snapshot_value["source_bindings"][
                        "generation11_runner_source_sha256"
                    ] = changed_source_sha256
                    mutated_snapshot_value["source_root_sha256"] = (
                        CONTRACTS.canonical_sha256(
                            mutated_snapshot_value["source_bindings"]
                        )
                    )
                    mutated_snapshot = self._reseal(
                        mutated_snapshot_value, "canonical_terminal_facts_sha256"
                    )
                    mutated_proof = replace(
                        mutated_proof, terminal_facts=mutated_snapshot
                    )
                    mutated_bindings.update(
                        {
                            "predecessor_terminal_facts_file_sha256": (
                                mutated_snapshot.raw_sha256
                            ),
                            "predecessor_terminal_facts_canonical_sha256": (
                                mutated_snapshot.value[
                                    "canonical_terminal_facts_sha256"
                                ]
                            ),
                            "predecessor_generation11_runner_source_sha256": (
                                changed_source_sha256
                            ),
                        }
                    )
                with (
                    patch.object(
                        CONTRACTS,
                        "GENERATION11_RUNNER_SOURCE_SHA256",
                        (
                            hashlib.sha256(
                                mutated_proof.generation11_runner_source_bytes
                            ).hexdigest()
                            if label == "source-bytes"
                            else source_hashes[0]
                        ),
                    ),
                    patch.object(
                        CONTRACTS,
                        "GENERATION11_SESSION_BOUNDARY_SOURCE_SHA256",
                        source_hashes[1],
                    ),
                ):
                    errors = CONTRACTS._validate_generation11_terminal_facts(
                        mutated_snapshot,
                        bindings=mutated_bindings,
                        proof=mutated_proof,
                        authorization=authorization,
                        manifest=manifest,
                        failure=failure,
                        repo_root=None,
                    )
                self.assertIn(expected, errors)

    def test_recovery_steering_binds_exact_zero_tool_sol_max_session(self) -> None:
        receipt, session, bindings, authorization, manifest, control_turn_id = (
            self.recovery_steering_fixture()
        )
        self.assertEqual(
            CONTRACTS._validate_generation11_recovery_steering(
                receipt,
                session,
                bindings=bindings,
                authorization=authorization,
                manifest=manifest,
                expected_control_turn_id=control_turn_id,
            ),
            [],
        )

    def test_recovery_steering_rejects_resealed_submission_model_tool_and_final(
        self,
    ) -> None:
        receipt, session, bindings, authorization, manifest, control_turn_id = (
            self.recovery_steering_fixture()
        )
        cases: list[tuple[str, dict, bytes]] = []

        changed_submission = deepcopy(receipt.value)
        changed_submission["submission_id"] = str(uuid.uuid4())
        cases.append(("submission", changed_submission, session))

        model_records = [json.loads(line) for line in session.splitlines()]
        model_records[7]["payload"]["model"] = "gpt-5.3-codex-spark"
        cases.append(("model", deepcopy(receipt.value), self._jsonl(model_records)))

        tool_records = [json.loads(line) for line in session.splitlines()]
        tool_records.insert(
            10,
            {
                "type": "response_item",
                "payload": {"type": "function_call", "name": "exec_command"},
            },
        )
        tool_value = deepcopy(receipt.value)
        tool_value["observed_activity"] = {
            "function_calls": 1,
            "custom_tool_calls": 0,
            "tool_item_types": ["function_call"],
            "compactions": 0,
            "workspace_mutations": 0,
        }
        cases.append(("tool", tool_value, self._jsonl(tool_records)))

        final_records = [json.loads(line) for line in session.splitlines()]
        final_records[12]["payload"]["message"] = "{}"
        cases.append(("final", deepcopy(receipt.value), self._jsonl(final_records)))

        for label, value, changed_session in cases:
            with self.subTest(label=label):
                changed_receipt, changed_bindings = self._reseal_recovery_fixture(
                    value, changed_session, bindings
                )
                errors = CONTRACTS._validate_generation11_recovery_steering(
                    changed_receipt,
                    changed_session,
                    bindings=changed_bindings,
                    authorization=authorization,
                    manifest=manifest,
                    expected_control_turn_id=control_turn_id,
                )
                if label == "tool":
                    self.assertIn(
                        "authorization-predecessor-v10-recovery-steering:steering-nonzero-activity",
                        errors,
                    )
                self.assertIn(
                    "authorization-predecessor-v10-recovery-steering-session-binding-invalid",
                    errors,
                )

    def test_recovery_steering_rejects_resealed_finding_severity(self) -> None:
        receipt, _session, bindings, authorization, manifest, control_turn_id = (
            self.recovery_steering_fixture()
        )
        changed_value = deepcopy(receipt.value)
        changed_value["opinion"]["findings"][0]["severity"] = "low"
        changed_session = self._recovery_session(
            opinion=changed_value["opinion"],
            session_id=changed_value["session_id"],
            submission_id=changed_value["submission_id"],
        )
        changed_receipt, changed_bindings = self._reseal_recovery_fixture(
            changed_value, changed_session, bindings
        )
        self.assertIn(
            "authorization-predecessor-v10-recovery-steering-binding-invalid",
            CONTRACTS._validate_generation11_recovery_steering(
                changed_receipt,
                changed_session,
                bindings=changed_bindings,
                authorization=authorization,
                manifest=manifest,
                expected_control_turn_id=control_turn_id,
            ),
        )

    def test_steering_adjudication_rejects_resealed_authority_changes(self) -> None:
        adjudication, authorization, manifest, receipt = (
            self.steering_adjudication_fixture()
        )
        self.assertEqual(
            CONTRACTS._validate_generation11_steering_adjudication(
                adjudication,
                gate="pre-live",
                authorization=authorization,
                manifest=manifest,
                receipt=receipt,
                source_hashes={
                    "opus-review-evidence": "6" * 64,
                    "opus-adjudication": "7" * 64,
                },
            ),
            [],
        )
        for field, value in (
            ("live_campaign_authorized", False),
            ("combined_confidence", 0.95),
            ("sol_session_id", str(uuid.uuid4())),
        ):
            with self.subTest(field=field):
                changed = deepcopy(adjudication.value)
                changed[field] = value
                resealed = self._reseal(changed, "canonical_adjudication_sha256")
                self.assertIn(
                    "authorization-predecessor-v10-pre-live-adjudication-binding-invalid",
                    CONTRACTS._validate_generation11_steering_adjudication(
                        resealed,
                        gate="pre-live",
                        authorization=authorization,
                        manifest=manifest,
                        receipt=receipt,
                        source_hashes={
                            "opus-review-evidence": "6" * 64,
                            "opus-adjudication": "7" * 64,
                        },
                    ),
                )

    def test_v32_containment_derives_every_nested_summary_from_sources(self) -> None:
        (
            containment,
            bindings,
            authorization,
            manifest,
            failure,
            proof,
            ledger_summary,
            expected_containment,
        ) = self.containment_fixture()
        self.assertEqual(
            CONTRACTS._validate_generation11_containment(
                containment,
                bindings=bindings,
                prior_authorization=authorization,
                prior_manifest=manifest,
                failure=failure,
                proof=proof,
                ledger_summary=ledger_summary,
                expected_containment=expected_containment,
            ),
            [],
        )

    def test_v32_containment_rejects_canonical_hash_in_raw_file_consumption_binding(
        self,
    ) -> None:
        (
            containment,
            bindings,
            authorization,
            manifest,
            failure,
            proof,
            ledger_summary,
            expected_containment,
        ) = self.containment_fixture()
        changed = deepcopy(containment.value)
        receipt = proof.pre_live_receipt
        adjudication = proof.pre_live_adjudication
        phase_nonce = proof.steering_registry.value["consumed"][1]["phase_nonce"]
        changed["steering_consumptions"]["pre-live"]["consumption_sha256"] = (
            CONTRACTS._domain_sha256(
                {
                    "receipt": receipt.value["canonical_receipt_sha256"],
                    "run": receipt.value["authorization_id"],
                    "attempt": receipt.value["submission_id"],
                    "gate": receipt.value["gate"],
                    "phase_nonce": phase_nonce,
                    "adjudication": adjudication.value[
                        "canonical_adjudication_sha256"
                    ],
                },
                domain="steering-receipt-consumption",
            )
        )
        changed_snapshot = self._reseal(changed, "canonical_recovery_sha256")
        changed_bindings = deepcopy(bindings)
        changed_bindings.update(
            {
                "predecessor_containment_file_sha256": changed_snapshot.raw_sha256,
                "predecessor_containment_canonical_sha256": changed_snapshot.value[
                    "canonical_recovery_sha256"
                ],
            }
        )
        errors = CONTRACTS._validate_generation11_containment(
            changed_snapshot,
            bindings=changed_bindings,
            prior_authorization=authorization,
            prior_manifest=manifest,
            failure=failure,
            proof=replace(proof, containment=changed_snapshot),
            ledger_summary=ledger_summary,
            expected_containment=expected_containment,
        )
        self.assertIn(
            "authorization-predecessor-v10-containment-steering-binding-invalid",
            errors,
        )

    def test_v32_containment_rejects_resealed_nested_contradictions(self) -> None:
        (
            containment,
            bindings,
            authorization,
            manifest,
            failure,
            proof,
            ledger_summary,
            expected_containment,
        ) = self.containment_fixture()

        def change(path: tuple[str, ...], value: object) -> dict:
            result = deepcopy(containment.value)
            current = result
            for key in path[:-1]:
                current = current[key]
            current[path[-1]] = value
            return result

        cases = (
            (
                "allocation-ledger",
                ("allocation_ledger", "sequence"),
                999,
                "authorization-predecessor-v10-containment-derived-summary-invalid",
            ),
            (
                "claim-scope",
                ("claim_v5_and_scope", "launch_claim_version"),
                4,
                "authorization-predecessor-v10-containment-claim-scope-binding-invalid",
            ),
            (
                "containment-summary",
                ("containment", "active_sessions"),
                1,
                "authorization-predecessor-v10-containment-derived-summary-invalid",
            ),
            (
                "steering-consumption",
                ("steering_consumptions", "pre-live", "consumed_exactly_once"),
                False,
                "authorization-predecessor-v10-containment-steering-binding-invalid",
            ),
            (
                "root-cause",
                ("root_cause", "replacement_read_attempted"),
                True,
                "authorization-predecessor-v10-containment-binding-invalid",
            ),
            (
                "failed-authority",
                ("failed_authority", "run_generation"),
                22,
                "authorization-predecessor-v10-containment-outer-authority-binding-invalid",
            ),
            (
                "terminal-failure",
                ("terminal_failure", "failure_class"),
                "Interrupted",
                "authorization-predecessor-v10-containment-binding-invalid",
            ),
            (
                "contained-session",
                ("contained_session", "archive_match_count"),
                2,
                "authorization-predecessor-v10-terminal-session-binding-invalid",
            ),
            (
                "recovery-contract",
                ("generation12_recovery_contract", "sol_confidence"),
                0.5,
                "authorization-predecessor-v10-containment-recovery-contract-binding-invalid",
            ),
            (
                "recovery-session",
                (
                    "generation12_recovery_contract",
                    "sol_session",
                    "attested_model",
                ),
                "gpt-5.3-codex-spark",
                "authorization-predecessor-v10-containment-recovery-contract-binding-invalid",
            ),
            (
                "disposition",
                ("disposition", "operative_dispatch_authorized"),
                True,
                "authorization-predecessor-v10-containment-binding-invalid",
            ),
            (
                "control-recheck",
                ("control_plane_recheck", "release_gate_passed"),
                True,
                "authorization-predecessor-v10-containment-control-recheck-binding-invalid",
            ),
        )
        for label, path, value, expected in cases:
            with self.subTest(label=label):
                changed_snapshot = self._reseal(
                    change(path, value), "canonical_recovery_sha256"
                )
                changed_bindings = deepcopy(bindings)
                changed_bindings.update(
                    {
                        "predecessor_containment_file_sha256": (
                            changed_snapshot.raw_sha256
                        ),
                        "predecessor_containment_canonical_sha256": (
                            changed_snapshot.value["canonical_recovery_sha256"]
                        ),
                    }
                )
                changed_proof = replace(proof, containment=changed_snapshot)
                errors = CONTRACTS._validate_generation11_containment(
                    changed_snapshot,
                    bindings=changed_bindings,
                    prior_authorization=authorization,
                    prior_manifest=manifest,
                    failure=failure,
                    proof=changed_proof,
                    ledger_summary=ledger_summary,
                    expected_containment=expected_containment,
                )
                self.assertIn(expected, errors)
if __name__ == "__main__":
    unittest.main()
