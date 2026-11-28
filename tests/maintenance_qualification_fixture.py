"""Providerless records for testing the installed maintenance reader and opaque join."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from cwo_core import maintenance_qualification as qualification
from cwo_core.maintenance_image import capture_control_image
from cwo_core.native_canary_contracts import canonical_sha256 as domain_hash
from cwo_core.native_turn_dispatch import TurnDispatchReservation, evolve_turn_dispatch_record
from tests.test_codex_tool_surface import synthetic_empty_endpoint_inventory


THREAD_ID = "fixture-thread"
TURN_ID = "fixture-turn"
PROMPT = "Synthetic fixture only: estimate one later bounded readonly command."
FIT = json.dumps({"decision": "accept", "tool_calls_p50": 1, "tool_calls_p90": 2,
                  "runtime_seconds_p50": 1, "runtime_seconds_p90": 2})


def _session_rows(model, workspace):
    return [
        {"type": "session_meta", "payload": {"id": THREAD_ID, "session_id": THREAD_ID, "cwd": workspace}},
        {"type": "event_msg", "payload": {"type": "task_started", "turn_id": TURN_ID}},
        {"type": "turn_context", "payload": {"turn_id": TURN_ID, "cwd": workspace, "model": model,
            "effort": "low", "approval_policy": "never", "sandbox_policy": {"type": "read-only"}}},
        {"type": "response_item", "payload": {"type": "message", "role": "user",
            "content": [{"type": "input_text", "text": PROMPT}]}},
        {"type": "response_item", "payload": {"type": "message", "role": "assistant",
            "phase": "final_answer", "content": [{"type": "output_text", "text": FIT}]}},
        {"type": "event_msg", "payload": {"type": "task_complete", "turn_id": TURN_ID,
            "last_agent_message": FIT}},
    ]


def _turn_dispatch(model, epoch, metadata):
    intent_id = "00000000-0000-4000-8000-000000000001"
    wire = {"id": 1, "method": "turn/start", "params": {"threadId": THREAD_ID,
        "input": [{"type": "text", "text": PROMPT, "text_elements": []}], "model": model, "effort": "low",
        "clientUserMessageId": intent_id, "responsesapiClientMetadata": metadata}}
    reservation = TurnDispatchReservation(thread_id=THREAD_ID, turn_intent_id=intent_id,
        request_id=1, connection_epoch_sha256=epoch, notification_cursor=0, preexisting_turn_ids=(),
        ledger_id=None, ledger_head_entry_sha256=None, turn_intent_entry_sha256=None,
        wire_request_sha256=domain_hash(wire, domain="app-server-single-wire-request"))
    return evolve_turn_dispatch_record(reservation.prepared_record(), status="acknowledged",
        exact_response_turn_id=TURN_ID, discovered_turn_ids=[TURN_ID], wire_write_attempt_count=1,
        ledger_resolution="turn-bound")


def write_fixture_observation(*, output, proof, operation, verifier, plan, metadata_rows=()):
    """Write one synthetic record with real pins, then issue only a test capability."""
    operation.revalidate(plan=plan)
    scope = operation.evidence()["operation"]
    model, workspace = scope["model"], scope["workspace"]
    image = capture_control_image()
    issued = dt.datetime.now(dt.timezone.utc)
    epoch, pid = "e" * 64, 4242
    home = Path(proof["codex_home"])
    start_path = home / "sessions" / "fixture-session.jsonl"
    final_path = home / "archived_sessions" / start_path.name
    final_path.parent.mkdir(parents=True)
    rows = _session_rows(model, workspace)
    rows[2:2] = metadata_rows
    final_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    raw, identity = qualification._owned_read(final_path)

    metadata = {"cwo_bead": plan["children"][0]["bead_id"], "cwo_control_turn": plan["transaction_id"],
                "cwo_mission": scope["mission_id"]}
    prompt_hash = qualification.digest(PROMPT.encode())
    proof_hash = qualification.canonical_sha256(proof)
    thread = {"id": THREAD_ID, "model": model, "cwd": workspace, "path": str(start_path), "turns": []}
    start = {"model": model, "cwd": workspace, "approvalPolicy": "never", "runtimeWorkspaceRoots": [workspace],
             "sandbox": {"type": "readOnly", "networkAccess": False}, "thread": thread}
    request = {"model": model, "allowProviderModelFallback": False, "cwd": workspace,
               "runtimeWorkspaceRoots": [workspace], "approvalPolicy": "never", "sandbox": "read-only",
               "ephemeral": False, "config": proof["lockdown_config"], "dynamicTools": [],
               "developerInstructions": "fixture no-tools precommit fit estimate"}
    terminal = {**thread, "turns": [{"id": TURN_ID, "status": "completed", "error": None, "items": [
        {"type": "userMessage", "content": [{"type": "text", "text": PROMPT}]},
        {"type": "agentMessage", "phase": "final_answer", "text": FIT}]}]}
    endpoints = synthetic_empty_endpoint_inventory(THREAD_ID, pid, epoch)
    evidence = {
        "intent.json": {"operation": scope, "plan_sha256": plan["plan_sha256"], "issued_at": issued.isoformat(),
                        "tool_surface_proof_sha256": proof_hash, "control_image_sha256": image["image_sha256"],
                        "prompt_sha256": prompt_hash, "operation_metadata": metadata, "qualification": False},
        "prompt.txt": PROMPT.encode(), "tool-surface.json": proof, "control-image.json": image,
        "process-start.json": {"pid": pid, "executable": proof["codex_binary"], "codex_home": str(home),
                               "connection_epoch_sha256": epoch, "requested_model": model, "reasoning_effort": "low"},
        "model-discovery.json": {"id": model, "model": model, "display_name": "synthetic fixture", "latency_ms": 0},
        "allocation-intent.json": {"mission_id": scope["mission_id"], "operation_id": scope["operation_id"],
                                   "allocation_id": "a" * 64, "ledger_sequence": 1},
        "thread-start.json": start, "thread-config.json": {"request": request, "response": start},
        "endpoint-inventory-before.json": endpoints, "endpoint-inventory-after.json": endpoints,
        "turn-intent.json": {"thread_id": THREAD_ID, "prompt_sha256": prompt_hash, "connection_epoch_sha256": epoch},
        "turn-start.json": {"id": TURN_ID}, "turn-dispatch.json": _turn_dispatch(model, epoch, metadata),
        "terminal.json": terminal, "session-before-closure.jsonl": raw, "session.jsonl": raw,
        "session-source.json": {"start_path": str(start_path), "path": str(final_path), "before_identity": identity,
                                "identity": identity, "sha256": qualification.digest(raw)},
        "archived-thread.json": {**terminal, "path": str(final_path)},
        "thread-closure.json": {"allocated_count": 1, "identified_thread_count": 1, "interrupted_count": 0,
                                "archived_count": 1, "already_contained_count": 0, "unresolved_allocation_intent_count": 0,
                                "unresolved_turn_intent_count": 0, "ambiguous_count": 0, "all_contained": True,
                                "ledger_consistent": True, "ledger_error_sha256": []},
        "process-closure.json": {"all_contained": True, "resources_closed": True, "errors": [], "pid": pid},
        "observation-times.json": {"source": "trusted-parent-monotonic-clock-v1", "pid": pid,
                                   "connection_epoch_sha256": epoch, "started_monotonic_ns": 1_000_000_000,
                                   "terminal_monotonic_ns": 2_000_000_000, "cleanup_complete_monotonic_ns": 3_000_000_000},
    }
    output.mkdir(mode=0o700)
    pins = {name: qualification.private_write(output, name, value) for name, value in evidence.items()}
    record = {"kind": "cwo-maintenance-qualification-observation", "version": 3, "mission_id": scope["mission_id"],
        "operation_sha256": operation.operation_sha256, "model": model, "origin_issued_at": issued.isoformat(),
        "origin_expires_at": (issued + dt.timedelta(minutes=15)).isoformat(), "pins": pins,
        "tool_profile_sha256": qualification.canonical_sha256(proof["requested_tools"]), "tool_surface_proof_sha256": proof_hash,
        "control_image_sha256": image["image_sha256"], "host_provenance_sha256": qualification.canonical_sha256(proof["capture_binding"]),
        "primary_error": None, "cleanup_errors": [], "qualified": False}
    report_hash = qualification.private_write(output, "observation.json", record)
    summary = qualification.inspect_observation(root=output, observation_sha256=report_hash)
    observed = qualification._mint(qualification.VerifiedQualificationObservation,
        operation=operation, verifier=verifier, record=record, root=output,
        root_identity=qualification._directory_identity(output), observation_sha256=report_hash,
        scope=scope, summary=summary, origin_code_pins=qualification._code_pins(), check_started=False)
    return observed, final_path
