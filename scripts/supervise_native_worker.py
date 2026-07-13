#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
from typing import Any

from cwo_core.native_session import (
    SEGMENT_START_EVENT,
    _evaluate_records,
    _is_user_boundary_record,
    _normalize_event_msg,
    _normalize_turn_context,
    _session_id_matches,
    session_file_trust_report,
)
from cwo_core.audit import acquire_audit_lock, record_audit_event, release_audit_lock
from cwo_core.native_disposition import derive_disposition
from cwo_core.native_retry import (
    build_retry_authorization,
    canonical_work_sha256,
    evaluate_retry_eligibility,
    validate_retry_authorization,
)
from cwo_core.policy import load_policy
from cwo_core.paths import AUDIT_LOG, cwo_temp_path, is_cwo_temp_path
from cwo_core.util import artifact_hash, atomic_write_text, make_dispatch_id
from prepare_native_worker import validate_native_worker_packet


STATE_TYPE = "cwo-native-supervision-state"
DECISION_TYPE = "cwo-native-supervision-decision"
STATE_SCHEMA = "schemas/native-supervision-state.schema.json"
DECISION_SCHEMA = "schemas/native-supervision-decision.schema.json"
FINAL_STATES = {"completed", "closed", "control-failed"}
EMPTY_USAGE = {"tool_calls": 0, "runtime_seconds": 0}


def _fail(message: str) -> None:
    raise SystemExit(message)


def _iso_now(value: str | None = None) -> dt.datetime:
    if value:
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            _fail(f"invalid --now value: {exc}")
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    return dt.datetime.now(dt.timezone.utc)


def _iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _elapsed_ms(start: str, end: dt.datetime) -> int:
    delta = end - _iso_now(start)
    return max(0, round(delta.total_seconds() * 1000))


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"could not load {label} {path}: {exc}")
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    return value


def _recovery_payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {
            "attempt": 0,
            "cumulative_usage": dict(EMPTY_USAGE),
            "eligibility": None,
            "authorization": None,
        }
    cumulative = value.get("cumulative_usage")
    usage = cumulative if isinstance(cumulative, dict) else {}
    for field in ("tool_calls", "runtime_seconds"):
        if not isinstance(usage.get(field), int) or isinstance(usage.get(field), bool):
            usage[field] = int(EMPTY_USAGE[field])
    return {
        "attempt": int(value.get("attempt", 0)) if isinstance(value.get("attempt"), int) and not isinstance(value.get("attempt"), bool) else 0,
        "cumulative_usage": {
            "tool_calls": int(usage["tool_calls"]),
            "runtime_seconds": int(usage["runtime_seconds"]),
        },
        "eligibility": value.get("eligibility"),
        "authorization": value.get("authorization"),
    }


def _retry_policy() -> dict[str, Any]:
    policy = load_policy("native-worker-execution").get("bounded_native_retry")
    if not isinstance(policy, dict):
        _fail("control-lost: bounded_native_retry policy is missing or invalid")
    return policy


def _require_state_packet(path: str | None, state: dict[str, Any], label: str) -> dict[str, Any]:
    if not path:
        _fail(f"{label}: supervision state missing packet_file binding")
    packet_path = Path(path).expanduser().resolve()
    packet = _load_json(packet_path, "packet")
    expected_sha256 = artifact_hash(json.dumps(packet, sort_keys=True))
    if state.get("packet_sha256") != expected_sha256:
        _fail("retry lifecycle requires preserved immutable work hash: packet artifact hash changed for this supervision state")
    return packet


def _require_closed_for_retry(state: dict[str, Any]) -> None:
    if state.get("status") != "closed":
        _fail("retry lifecycle requires a closed supervision state")
    receipts = state.get("control_receipts", [])
    if not isinstance(receipts, list):
        _fail("retry lifecycle requires control receipts list in state")
    for required in ("interrupt-confirmed", "close-confirmed"):
        if required not in receipts:
            _fail("retry lifecycle requires interrupt-confirmed and close-confirmed control receipts")


def _require_native_retry_decision(state: dict[str, Any]) -> None:
    if state.get("decision") != "interrupt":
        _fail("retry lifecycle requires decision=interrupt; control-lost is a protected stop")


def _read_session(path: Path) -> tuple[list[dict[str, Any]], bool]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        _fail(f"control-lost: could not read session file {path}: {exc}")
    records: list[dict[str, Any]] = []
    lines = text.splitlines(keepends=True)
    trailing_partial = False
    for index, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            if index == len(lines) and not line.endswith(("\n", "\r")):
                trailing_partial = True
                continue
            _fail(f"control-lost: malformed completed JSONL record at line {index}: {exc}")
        if not isinstance(value, dict):
            _fail(f"control-lost: session record {index} is not an object")
        records.append(value)
    if not records:
        _fail("control-lost: session file has no complete records")
    return records, trailing_partial


def _trusted_models(records: list[dict[str, Any]]) -> set[str]:
    result: set[str] = set()
    for record in records:
        context = _normalize_turn_context(record)
        if isinstance(context, dict) and isinstance(context.get("model"), str):
            model = context["model"].strip()
            if model:
                result.add(model)
    return result


def _state_path(packet: dict[str, Any], session_id: str, raw: str | None) -> Path:
    path = Path(raw).expanduser() if raw else cwo_temp_path(
        f"{packet['packet_id']}-{session_id}.json",
        purpose="native-supervision",
    )
    path = path.resolve()
    if not is_cwo_temp_path(path):
        _fail("supervision state must be under a CWO-owned temporary directory")
    return path


def _write_state(path: Path, state: dict[str, Any]) -> None:
    lock, _ = acquire_audit_lock(path)
    try:
        atomic_write_text(path, json.dumps(state, indent=2, sort_keys=True) + "\n")
    finally:
        release_audit_lock(lock)


def _decision(state: dict[str, Any]) -> dict[str, Any]:
    recovery = _recovery_payload(state.get("recovery"))
    return {
        "result_type": DECISION_TYPE,
        "version": 1,
        "schema": DECISION_SCHEMA,
        "state_id": state["state_id"],
        "packet_id": state["packet_id"],
        "session_id": state["session_id"],
        "decision": state["decision"],
        "reasons": list(state.get("reasons", [])),
        "immutable_work_sha256": state.get("immutable_work_sha256"),
        "observed": dict(state.get("observed", {})),
        "interrupt_thresholds": dict(state["interrupt_thresholds"]),
        "control_turn_id": state.get("control_turn_id"),
        "control_timing": dict(state["control_timing"]),
        "control_action_required": bool(state.get("control_action_required")),
        "recovery": dict(recovery),
        "session_disposition": state["session_disposition"],
        "artifact_disposition": state["artifact_disposition"],
        "artifact_validation": dict(state["artifact_validation"]),
        "trailing_partial_record_ignored": bool(state.get("trailing_partial_record_ignored")),
    }


def _audit_event(
    state: dict[str, Any],
    event_type: str,
    *,
    control_action: str | None = None,
) -> dict[str, Any]:
    observed = state.get("observed", {})
    recovery = _recovery_payload(state.get("recovery"))
    eligibility = recovery.get("eligibility") if isinstance(recovery.get("eligibility"), dict) else {}
    authorization = recovery.get("authorization") if isinstance(recovery.get("authorization"), dict) else {}
    budget = state["budget"]
    thresholds = state["interrupt_thresholds"]
    timing = state["control_timing"]
    decision = str(state.get("decision") or "continue")
    delegation_status = {
        "continue": "started",
        "warn": "started",
        "complete": "completed",
        "interrupt": "blocked",
        "control-lost": "blocked",
    }.get(decision, "started")
    include_plan = event_type == "native_supervision_started"
    include_actual = include_plan or (
        event_type == "native_supervision_decision"
        and decision in {"complete", "interrupt", "control-lost"}
    )
    include_usage = event_type == "native_supervision_decision" and decision in {
        "complete",
        "interrupt",
        "control-lost",
    }
    return record_audit_event(
        {
            "event_type": event_type,
            "telemetry_kind": "native_supervision",
            "telemetry_status": decision,
            "dispatch_id": state["packet_id"],
            "packet_sha256": state["packet_sha256"],
            "bead_id": state["bead_id"],
            "session_id": state["session_id"],
            "native_supervision_state_id": state["state_id"],
            "native_supervision_required": True,
            "native_supervision_status": state["status"],
            "native_supervision_decision": decision,
            "native_supervision_reasons": state.get("reasons", []),
            "model": state["requested_model"],
            "role": state["lane"],
            "control_adapter": state["control_adapter"],
            "control_turn_id": state.get("control_turn_id"),
            "submission_id": state.get("submission_id"),
            "monitor_armed_before_dispatch": timing.get("monitor_armed_before_dispatch"),
            "arm_to_dispatch_ms": timing.get("arm_to_dispatch_ms"),
            "dispatch_to_first_poll_ms": timing.get("dispatch_to_first_poll_ms"),
            "max_poll_gap_ms": timing.get("max_poll_gap_ms"),
            "late_poll_count": timing.get("late_poll_count"),
            "poll_interval_ms": state["poll_interval_ms"],
            "poll_lag_tolerance_ms": state["poll_lag_tolerance_ms"],
            "control_action": control_action,
            "control_action_required": bool(state.get("control_action_required")),
            "control_receipt_confirmed": control_action is not None,
            "control_receipts": state.get("control_receipts", []),
            "trailing_partial_record_ignored": bool(state.get("trailing_partial_record_ignored")),
            "planned_tool_calls_hard": budget["tool_calls_hard"],
            "interrupt_tool_calls_threshold": thresholds["tool_calls"],
            "observed_tool_calls": observed.get("tool_calls", 0),
            "planned_runtime_seconds_hard": budget["runtime_seconds_hard"],
            "interrupt_runtime_seconds_threshold": thresholds["runtime_seconds"],
            "observed_runtime_seconds": observed.get("elapsed_seconds", 0),
            "observed_context_compactions": observed.get("context_compactions", 0),
            "observed_full_suite_runs": observed.get("full_suite_runs", 0),
            "validation_lineage_attempt": state["validation_lineage"]["attempt"],
            "agent_model_calls": observed.get("tool_calls", 0) if include_usage else None,
            "elapsed_seconds": observed.get("elapsed_seconds", 0) if include_usage else None,
            "workerbee_planned_mode": "implementation-capable" if include_plan else None,
            "workerbee_planned_model": state["requested_model"] if include_plan else None,
            "workerbee_planned_lanes": [state["lane"]] if include_plan else [],
            "workerbee_actual_mode": "implementation-capable" if include_actual else None,
            "workerbee_actual_model": state["requested_model"] if include_actual else None,
            "workerbee_actual_lanes": [state["lane"]] if include_actual else [],
            "workerbee_delegation_status": delegation_status if include_actual else None,
            "workerbee_delegation_source": "trusted-native-supervisor" if include_actual else None,
            "completion_state": state["status"],
            "session_disposition": state["session_disposition"],
            "artifact_disposition": state["artifact_disposition"],
            "artifact_validation": state["artifact_validation"],
            "native_retry_work_sha256": state.get("immutable_work_sha256"),
            "native_retry_attempt": recovery.get("attempt"),
            "native_retry_eligibility": eligibility,
            "native_retry_eligibility_reasons": eligibility.get("reasons"),
            "native_retry_next_action": eligibility.get("next_action"),
            "native_retry_receipt_sha256": authorization.get("receipt_sha256"),
            "native_retry_cumulative_usage": recovery.get("cumulative_usage"),
            "native_retry_remaining_before_retry": eligibility.get("remaining_before_retry"),
        },
        Path(state["audit_file"]),
    )


def start(args: argparse.Namespace) -> dict[str, Any]:
    packet_path = Path(args.packet).expanduser().resolve()
    packet = _load_json(packet_path, "packet")
    errors = validate_native_worker_packet(packet, dispatchable=True)
    if errors:
        _fail("packet validation failed: " + "; ".join(errors))
    session_file = Path(args.session_file).expanduser().resolve()
    if not session_file.is_file() or not _session_id_matches(session_file, args.session_id):
        _fail("control-lost: session file identity does not match --session-id")
    trust = session_file_trust_report(session_file)
    if not trust["trusted"]:
        _fail(
            "control-lost: session file failed the trusted-telemetry invariant: "
            + "; ".join(trust["reasons"])
        )
    records, trailing = _read_session(session_file)
    models = _trusted_models(records)
    requested_model = str(packet["requested_model"])
    if models != {requested_model}:
        _fail(f"control-lost: trusted attestation mismatch: expected {requested_model!r}, observed {sorted(models)!r}")
    path = _state_path(packet, args.session_id, args.state_file)
    if path.exists():
        previous = _load_json(path, "supervision state")
        if previous.get("status") not in FINAL_STATES:
            _fail("duplicate active supervision state for packet/session")
        _fail("finalized supervision state cannot be reopened")
    now = _iso_now(args.now)
    clean_budget = {key: int(value) for key, value in packet["budget"].items()}
    disposition = derive_disposition(
        status="within-budget",
        requested_model=requested_model,
        actual_model=requested_model,
        usage={"tool_calls": 0, "elapsed_seconds": 0, "context_compactions": 0, "full_suite_runs": 0},
        budget=clean_budget,
    )
    immutable_work_sha256 = canonical_work_sha256(packet)
    recovery = _recovery_payload(None)
    retry_authorization = None
    if args.retry_authorization:
        authorization = _load_json(Path(args.retry_authorization).expanduser().resolve(), "retry authorization")
        errors = validate_retry_authorization(authorization)
        if errors:
            _fail("retry authorization validation failed: " + "; ".join(errors))
        if authorization["retry_packet_id"] != packet["packet_id"]:
            _fail("retry authorization packet mismatch")
        if authorization["bead_id"] != packet["bead_id"]:
            _fail("retry authorization bead mismatch")
        if authorization["requested_model"] != requested_model or authorization["attested_model"] != requested_model:
            _fail("retry authorization model mismatch")
        if authorization["attempt_from"] != 0 or authorization["attempt_to"] != 1:
            _fail("retry authorization attempt lineage must be 0->1")
        if authorization["work_sha256"] != immutable_work_sha256:
            _fail("retry authorization work hash mismatch")
        recovery = _recovery_payload({
            "attempt": int(authorization["attempt_to"]),
            "cumulative_usage": authorization["cumulative_usage"],
            "eligibility": None,
            "authorization": authorization,
        })
    state = {
        "result_type": STATE_TYPE,
        "version": 1,
        "schema": STATE_SCHEMA,
        "state_id": make_dispatch_id(f"supervision-{packet['packet_id']}"),
        "packet_id": packet["packet_id"],
        "packet_sha256": artifact_hash(json.dumps(packet, sort_keys=True)),
        "packet_file": str(packet_path),
        "bead_id": packet["bead_id"],
        "lane": packet["lane"],
        "agent_id": args.agent_id,
        "session_id": args.session_id,
        "session_file": str(session_file),
        "baseline_record_count": len(records),
        "requested_model": requested_model,
        "budget": clean_budget,
        "budget_provenance": packet["budget_provenance"],
        "interrupt_thresholds": packet["supervision"]["interrupt_thresholds"],
        "poll_interval_ms": packet["supervision"]["poll_interval_ms"],
        "poll_lag_tolerance_ms": packet["supervision"]["poll_lag_tolerance_ms"],
        "arm_to_dispatch_max_ms": packet["supervision"]["arm_to_dispatch_max_ms"],
        "control_turn_required": packet["supervision"]["control_turn_required"],
        "segment_start_grace_seconds": packet["supervision"]["segment_start_grace_seconds"],
        "control_adapter": packet["supervision"]["control_adapter"],
        "required_capabilities": packet["supervision"]["required_capabilities"],
        "immutable_work_sha256": immutable_work_sha256,
        "validation_lineage": packet["validation_lineage"],
        "recovery": recovery,
        "audit_file": str(Path(args.audit_file).expanduser().resolve() if args.audit_file else AUDIT_LOG.resolve()),
        "status": "created",
        "decision": "continue",
        "reasons": [],
        "control_action_required": False,
        "control_receipts": [],
        "observed": {"tool_calls": 0, "elapsed_seconds": 0, "context_compactions": 0, "full_suite_runs": 0},
        "session_disposition": disposition["session_disposition"],
        "artifact_disposition": disposition["artifact_disposition"],
        "artifact_validation": disposition["artifact_validation"],
        "trailing_partial_record_ignored": trailing,
        "started_at": _iso(now),
        "updated_at": _iso(now),
        "finalized_at": None,
        "last_audited_decision": "continue",
        "control_turn_id": None,
        "submission_id": None,
        "control_timing": {
            "monitor_armed_before_dispatch": False,
            "armed_at": None,
            "dispatched_at": None,
            "first_poll_at": None,
            "last_poll_at": None,
            "arm_to_dispatch_ms": None,
            "dispatch_to_first_poll_ms": None,
            "max_poll_gap_ms": 0,
            "late_poll_count": 0,
        },
    }
    _write_state(path, state)
    _audit_event(state, "native_supervision_started")
    state["state_file"] = str(path)
    return state


def _load_control_state(path_value: str) -> tuple[Path, dict[str, Any]]:
    path = Path(path_value).expanduser().resolve()
    if not is_cwo_temp_path(path):
        _fail("supervision state must be under a CWO-owned temporary directory")
    return path, _load_json(path, "supervision state")


def _control_turn(value: str) -> str:
    control_turn_id = str(value or "").strip()
    if not control_turn_id:
        _fail("control-turn-id must be non-empty")
    return control_turn_id


def _require_control_turn(state: dict[str, Any], value: str) -> str:
    control_turn_id = _control_turn(value)
    if state.get("control_turn_id") != control_turn_id:
        _fail("control-turn-id does not match the armed supervisor state")
    return control_turn_id


def _set_control_lost(
    state: dict[str, Any],
    *,
    reason: str,
    now: dt.datetime,
    validation_reason: str,
) -> None:
    state.update(
        {
            "decision": "control-lost",
            "status": "interrupt-pending",
            "reasons": [reason],
            "control_action_required": True,
            "session_disposition": "quarantined",
            "artifact_disposition": "architect-adjudication-required",
            "artifact_validation": {
                "eligible": False,
                "max_attempts": 1,
                "attempts_used": 0,
                "outcome": "not-run",
                "reason": validation_reason,
            },
            "updated_at": _iso(now),
        }
    )


def arm(args: argparse.Namespace) -> dict[str, Any]:
    path, state = _load_control_state(args.state_file)
    if state.get("status") != "created":
        _fail("arm requires a newly created supervision state")
    now = _iso_now(args.now)
    state["control_turn_id"] = _control_turn(args.control_turn_id)
    state["status"] = "armed"
    state["control_timing"]["armed_at"] = _iso(now)
    state["updated_at"] = _iso(now)
    _audit_event(state, "native_supervision_armed")
    _write_state(path, state)
    return state


def mark_dispatched(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    path, state = _load_control_state(args.state_file)
    if state.get("status") != "armed":
        _fail("mark-dispatched requires an armed supervision state")
    supplied_control_turn = _control_turn(args.control_turn_id)
    submission_id = str(args.submission_id or "").strip()
    if not submission_id:
        _fail("submission-id must be non-empty")
    now = _iso_now(args.now)
    timing = state["control_timing"]
    arm_to_dispatch_ms = _elapsed_ms(timing["armed_at"], now)
    timing["arm_to_dispatch_ms"] = arm_to_dispatch_ms
    timing["dispatched_at"] = _iso(now)
    state["submission_id"] = submission_id
    state["updated_at"] = _iso(now)
    control_failure = None
    validation_reason = None
    if state.get("control_turn_id") != supplied_control_turn:
        control_failure = "control-turn-mismatch-after-dispatch"
        validation_reason = "dispatch control-turn binding lost"
    elif arm_to_dispatch_ms > state["arm_to_dispatch_max_ms"]:
        control_failure = "arm-to-dispatch-latency-exceeded"
        validation_reason = "arm-to-dispatch control timing lost"
    if control_failure:
        _set_control_lost(
            state,
            reason=control_failure,
            now=now,
            validation_reason=str(validation_reason),
        )
        _audit_event(state, "native_supervision_decision")
        state["last_audited_decision"] = "control-lost"
        _write_state(path, state)
        return state, 2
    timing["monitor_armed_before_dispatch"] = True
    state["status"] = "running"
    _audit_event(state, "native_supervision_dispatched")
    _write_state(path, state)
    return state, 0


def _record_poll_timing(state: dict[str, Any], now: dt.datetime) -> bool:
    timing = state["control_timing"]
    reference = timing.get("last_poll_at") or timing.get("dispatched_at")
    if not reference:
        _fail("control-lost: dispatched supervisor state has no poll reference")
    gap_ms = _elapsed_ms(reference, now)
    if timing.get("first_poll_at") is None:
        timing["first_poll_at"] = _iso(now)
        timing["dispatch_to_first_poll_ms"] = gap_ms
    timing["last_poll_at"] = _iso(now)
    timing["max_poll_gap_ms"] = max(int(timing.get("max_poll_gap_ms") or 0), gap_ms)
    allowed_gap_ms = state["poll_interval_ms"] + state["poll_lag_tolerance_ms"]
    if gap_ms > allowed_gap_ms:
        timing["late_poll_count"] = int(timing.get("late_poll_count") or 0) + 1
        return True
    return False


def check(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    path, state = _load_control_state(args.state_file)
    if state.get("status") in {"running", "interrupt-pending", "interrupt-confirmed"}:
        try:
            _require_control_turn(state, args.control_turn_id)
        except SystemExit:
            now = _iso_now(args.now)
            _set_control_lost(
                state,
                reason="control-turn-mismatch-during-monitoring",
                now=now,
                validation_reason="live monitoring control-turn binding lost",
            )
            if state.get("last_audited_decision") != "control-lost":
                _audit_event(state, "native_supervision_decision")
                state["last_audited_decision"] = "control-lost"
            _write_state(path, state)
            return _decision(state), 2
    else:
        _require_control_turn(state, args.control_turn_id)
    if state.get("status") in FINAL_STATES:
        return _decision(state), 2 if state.get("decision") == "control-lost" else 0
    if state.get("status") not in {"running", "interrupt-pending", "interrupt-confirmed"}:
        _fail("check requires a marked-dispatched supervision state")
    now = _iso_now(args.now)
    previous_audited_decision = state.get("last_audited_decision")
    poll_latency_exceeded = _record_poll_timing(state, now)
    try:
        trust = session_file_trust_report(Path(state["session_file"]))
        if not trust["trusted"]:
            _fail(
                "control-lost: session file failed the trusted-telemetry invariant: "
                + "; ".join(trust["reasons"])
            )
        all_records, trailing = _read_session(Path(state["session_file"]))
        baseline_record_count = state["baseline_record_count"]
        if len(all_records) < baseline_record_count:
            _fail("control-lost: session log was truncated below the supervision watermark")
        records = all_records[baseline_record_count:]
        has_boundary = any(
            _normalize_event_msg(record) == SEGMENT_START_EVENT
            or _is_user_boundary_record(record)
            for record in records
            if isinstance(record, dict)
        )
        if not has_boundary:
            if poll_latency_exceeded:
                _fail("control-lost: poll latency exceeded the configured interval and tolerance")
            dispatched_at = _iso_now(state["control_timing"]["dispatched_at"])
            elapsed = max(0.0, (now - dispatched_at).total_seconds())
            if elapsed <= state["segment_start_grace_seconds"]:
                state.update(
                    {
                        "decision": "continue",
                        "status": "running",
                        "reasons": ["awaiting-task-boundary"],
                        "control_action_required": False,
                        "trailing_partial_record_ignored": trailing,
                        "updated_at": _iso(now),
                    }
                )
                _write_state(path, state)
                return _decision(state), 0
            _fail("control-lost: task boundary did not appear within startup grace")
        segments, aggregate, overall_status, selected = _evaluate_records(
            records,
            state["budget"],
            state["requested_model"],
            now,
        )
        _ = segments
        _ = aggregate
        observed = {
            "tool_calls": int(selected["tool_calls"]),
            "elapsed_seconds": float(selected["runtime_seconds"]),
            "context_compactions": int(selected["context_compactions"]),
            "full_suite_runs": int(selected["full_suite_runs"]),
        }
        state["observed"] = observed
        if poll_latency_exceeded:
            _fail("control-lost: poll latency exceeded the configured interval and tolerance")
        reasons: list[str] = []
        if overall_status == "model-mismatch":
            reasons.append("model-mismatch")
        if observed["context_compactions"] > state["budget"]["max_compactions"]:
            reasons.append("context-compaction")
        if observed["full_suite_runs"] > state["budget"]["max_full_suite_runs"]:
            reasons.append("full-suite-limit")
        if observed["tool_calls"] >= state["interrupt_thresholds"]["tool_calls"]:
            reasons.append("tool-call-interrupt-threshold")
        if observed["elapsed_seconds"] >= state["interrupt_thresholds"]["runtime_seconds"]:
            reasons.append("runtime-interrupt-threshold")
        complete = bool(selected.get("complete"))
        if reasons:
            decision = "interrupt"
        elif complete:
            decision = "complete"
        elif observed["tool_calls"] > state["budget"]["tool_calls_soft"] or observed["elapsed_seconds"] > state["budget"]["runtime_seconds_soft"]:
            decision = "warn"
        else:
            decision = "continue"
        disposition = {
            "session_disposition": selected["session_disposition"],
            "artifact_disposition": selected["artifact_disposition"],
            "artifact_validation": selected["artifact_validation"],
        }
        if decision == "interrupt" and disposition["session_disposition"] != "quarantined":
            disposition = {
                "session_disposition": "quarantined",
                "artifact_disposition": "independent-validation-required",
                "artifact_validation": {
                    "eligible": True,
                    "max_attempts": 1,
                    "attempts_used": 0,
                    "outcome": "not-run",
                    "reason": "reserved live budget threshold reached",
                },
            }
        state.update(
            {
                "decision": decision,
                "status": "interrupt-pending" if decision == "interrupt" else state["status"],
                "reasons": reasons,
                "control_action_required": decision == "interrupt",
                "observed": observed,
                "trailing_partial_record_ignored": trailing,
                "updated_at": _iso(now),
                **disposition,
            }
        )
    except SystemExit as exc:
        state.update(
            {
                "decision": "control-lost",
                "status": "interrupt-pending",
                "reasons": [str(exc)],
                "control_action_required": True,
                "session_disposition": "quarantined",
                "artifact_disposition": "architect-adjudication-required",
                "artifact_validation": {
                    "eligible": False,
                    "max_attempts": 1,
                    "attempts_used": 0,
                    "outcome": "not-run",
                    "reason": "live telemetry or control state lost",
                },
                "updated_at": _iso(now),
            }
        )
    if state.get("decision") != previous_audited_decision:
        _audit_event(state, "native_supervision_decision")
        state["last_audited_decision"] = state.get("decision")
    _write_state(path, state)
    decision = _decision(state)
    return decision, 2 if decision["decision"] in {"interrupt", "control-lost"} else 0


def finalize(args: argparse.Namespace) -> dict[str, Any]:
    path, state = _load_control_state(args.state_file)
    _require_control_turn(state, args.control_turn_id)
    if state.get("status") in FINAL_STATES:
        _fail("finalized supervision state cannot be reopened")
    action = args.control_action
    if action == "worker-completed" and state.get("decision") != "complete":
        _fail("worker-completed requires a complete supervisor decision")
    if action == "interrupt-confirmed" and state.get("decision") not in {"interrupt", "control-lost"}:
        _fail("interrupt-confirmed requires an interrupt or control-lost supervisor decision")
    receipts = list(state.get("control_receipts", []))
    receipts.append(action)
    state["control_receipts"] = receipts
    if action == "interrupt-confirmed":
        state["status"] = "interrupt-confirmed"
    elif action == "close-confirmed":
        if "interrupt-confirmed" not in receipts:
            _fail("close-confirmed requires an interrupt-confirmed receipt")
        state["status"] = "closed"
        state["control_action_required"] = False
        state["finalized_at"] = _iso(_iso_now(args.now))
    elif action == "worker-completed":
        state["status"] = "completed"
        state["decision"] = "complete"
        state["control_action_required"] = False
        state["finalized_at"] = _iso(_iso_now(args.now))
    elif action == "control-failed":
        state["status"] = "control-failed"
        state["decision"] = "control-lost"
        state["session_disposition"] = "quarantined"
        state["artifact_disposition"] = "architect-adjudication-required"
        state["control_action_required"] = False
        state["finalized_at"] = _iso(_iso_now(args.now))
    state["updated_at"] = _iso(_iso_now(args.now))
    _audit_event(state, "native_supervision_control_receipt", control_action=action)
    _write_state(path, state)
    return state


def assess_retry(args: argparse.Namespace) -> dict[str, Any]:
    path, state = _load_control_state(args.state_file)
    _require_control_turn(state, args.control_turn_id)
    _require_closed_for_retry(state)
    _require_native_retry_decision(state)
    parent = _require_state_packet(state.get("packet_file"), state, "parent packet")
    canonical = canonical_work_sha256(parent)
    if state.get("immutable_work_sha256") != canonical:
        _fail("retry lifecycle requires preserved immutable work hash")
    workspace_report = _load_json(Path(args.workspace_report).expanduser().resolve(), "workspace report")
    semantic_result = _load_json(Path(args.semantic_result).expanduser().resolve(), "semantic result")
    policy = _retry_policy()
    eligibility = evaluate_retry_eligibility(
        packet=parent,
        supervision_state=state,
        workspace_report=workspace_report,
        semantic_result=semantic_result,
        recovery_policy=policy,
    )
    recovery = _recovery_payload(state.get("recovery"))
    recovery["eligibility"] = dict(eligibility)
    state["recovery"] = recovery
    state["updated_at"] = _iso(_iso_now(args.now))
    _audit_event(state, "native_retry_assessed")
    _write_state(path, state)
    return eligibility


def authorize_retry(args: argparse.Namespace) -> dict[str, Any]:
    path, state = _load_control_state(args.state_file)
    _require_control_turn(state, args.control_turn_id)
    _require_closed_for_retry(state)
    _require_native_retry_decision(state)
    parent = _require_state_packet(state.get("packet_file"), state, "parent packet")
    canonical = canonical_work_sha256(parent)
    if state.get("immutable_work_sha256") != canonical:
        _fail("retry lifecycle requires preserved immutable work hash")
    workspace_report = _load_json(Path(args.workspace_report).expanduser().resolve(), "workspace report")
    semantic_result = _load_json(Path(args.semantic_result).expanduser().resolve(), "semantic result")
    fresh_attestation = _load_json(Path(args.fresh_attestation).expanduser().resolve(), "fresh attestation")
    retry_packet = _load_json(Path(args.retry_packet).expanduser().resolve(), "retry packet")
    errors = validate_native_worker_packet(retry_packet, dispatchable=True)
    if errors:
        _fail("retry packet validation failed: " + "; ".join(errors))
    policy = _retry_policy()
    current = evaluate_retry_eligibility(
        packet=parent,
        supervision_state=state,
        workspace_report=workspace_report,
        semantic_result=semantic_result,
        recovery_policy=policy,
    )
    stored = state.get("recovery", {}).get("eligibility")
    if stored != current:
        _fail("retry requires re-assessing with the same inputs and policy")
    authorization = build_retry_authorization(
        parent_packet=parent,
        retry_packet=retry_packet,
        supervision_state=state,
        workspace_report=workspace_report,
        semantic_result=semantic_result,
        recovery_policy=policy,
        fresh_attestation=fresh_attestation,
    )
    validation_errors = validate_retry_authorization(authorization)
    if validation_errors:
        _fail("retry authorization validation failed: " + "; ".join(validation_errors))
    recovery = _recovery_payload(state.get("recovery"))
    recovery["authorization"] = authorization
    state["recovery"] = recovery
    state["updated_at"] = _iso(_iso_now(args.now))
    _audit_event(state, "native_retry_authorized")
    _write_state(path, state)
    return authorization


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Supervise one native worker against packet-v2 live budgets.")
    commands = parser.add_subparsers(dest="command", required=True)
    start_cmd = commands.add_parser("start")
    start_cmd.add_argument("--packet", required=True)
    start_cmd.add_argument("--session-id", required=True)
    start_cmd.add_argument("--session-file", required=True)
    start_cmd.add_argument("--agent-id", required=True)
    start_cmd.add_argument("--audit-file")
    start_cmd.add_argument("--state-file")
    start_cmd.add_argument("--retry-authorization")
    start_cmd.add_argument("--now")
    start_cmd.add_argument("--json", action="store_true")
    arm_cmd = commands.add_parser("arm")
    arm_cmd.add_argument("--state-file", required=True)
    arm_cmd.add_argument("--control-turn-id", required=True)
    arm_cmd.add_argument("--now")
    arm_cmd.add_argument("--json", action="store_true")
    dispatched_cmd = commands.add_parser("mark-dispatched")
    dispatched_cmd.add_argument("--state-file", required=True)
    dispatched_cmd.add_argument("--control-turn-id", required=True)
    dispatched_cmd.add_argument("--submission-id", required=True)
    dispatched_cmd.add_argument("--now")
    dispatched_cmd.add_argument("--json", action="store_true")
    check_cmd = commands.add_parser("check")
    check_cmd.add_argument("--state-file", required=True)
    check_cmd.add_argument("--control-turn-id", required=True)
    check_cmd.add_argument("--now")
    check_cmd.add_argument("--json", action="store_true")
    finalize_cmd = commands.add_parser("finalize")
    finalize_cmd.add_argument("--state-file", required=True)
    finalize_cmd.add_argument("--control-turn-id", required=True)
    finalize_cmd.add_argument("--control-action", required=True, choices=["interrupt-confirmed", "close-confirmed", "worker-completed", "control-failed"])
    finalize_cmd.add_argument("--now")
    finalize_cmd.add_argument("--json", action="store_true")
    assess_cmd = commands.add_parser("assess-retry")
    assess_cmd.add_argument("--state-file", required=True)
    assess_cmd.add_argument("--control-turn-id", required=True)
    assess_cmd.add_argument("--workspace-report", required=True)
    assess_cmd.add_argument("--semantic-result", required=True)
    assess_cmd.add_argument("--now")
    assess_cmd.add_argument("--json", action="store_true")
    authorize_cmd = commands.add_parser("authorize-retry")
    authorize_cmd.add_argument("--state-file", required=True)
    authorize_cmd.add_argument("--control-turn-id", required=True)
    authorize_cmd.add_argument("--retry-packet", required=True)
    authorize_cmd.add_argument("--fresh-attestation", required=True)
    authorize_cmd.add_argument("--workspace-report", required=True)
    authorize_cmd.add_argument("--semantic-result", required=True)
    authorize_cmd.add_argument("--now")
    authorize_cmd.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "start":
        result, code = start(args), 0
    elif args.command == "arm":
        result, code = arm(args), 0
    elif args.command == "mark-dispatched":
        result, code = mark_dispatched(args)
    elif args.command == "check":
        result, code = check(args)
    elif args.command == "finalize":
        result, code = finalize(args), 0
    elif args.command == "assess-retry":
        result, code = assess_retry(args), 0
    elif args.command == "authorize-retry":
        result, code = authorize_retry(args), 0
    else:
        _fail(f"unsupported command {args.command!r}")
    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"{args.command}: {result.get('decision', result.get('status'))}")
        if result.get("state_file"):
            print(f"state_file: {result['state_file']}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
