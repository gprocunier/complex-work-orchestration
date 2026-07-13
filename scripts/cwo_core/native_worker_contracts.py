"""Contracts and deterministic evidence helpers for native worker execution.

The v3 structures in this module are intentionally inert.  They describe the
future evidence contract but do not authorize dispatch or replay.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import shlex
from dataclasses import dataclass
from typing import Any, Mapping

from .native_disposition import DISPOSITION_FIELDS
from .util import artifact_hash

ALLOWED_PACKET_FIELDS = {
    "packet_type",
    "version",
    "packet_id",
    "bead_id",
    "lane",
    "requested_model",
    "session_policy",
    "scope",
    "acceptance_checks",
    "budget",
    "budget_provenance",
    "supervision",
    "validation_lineage",
    "escalation_triggers",
    "return_contract",
    "work_plan",
    "worker_commitment",
    "command_contract",
}
ALLOWED_SESSION_POLICY_FIELDS = {
    "fresh_session_required",
    "resume_forbidden",
    "attestation",
    "source",
}
ALLOWED_ATTESTATION_FIELDS = {
    "required",
    "tool_mode",
    "model_authority",
    "self_report_authority",
    "required_actual_model",
}
ALLOWED_SCOPE_FIELDS = {
    "workdir",
    "allowed_paths",
    "allowed_actions",
    "prohibited_actions",
}
ALLOWED_BUDGET_FIELDS = {
    "tool_calls_soft",
    "tool_calls_hard",
    "runtime_seconds_soft",
    "runtime_seconds_hard",
    "max_compactions",
    "max_full_suite_runs",
}
ALLOWED_BUDGET_PROVENANCE_FIELDS = {
    "profile",
    "policy_source",
    "overrides_applied",
    "overridden_fields",
}
ALLOWED_SUPERVISION_FIELDS = {
    "required",
    "mode",
    "poll_interval_ms",
    "poll_lag_tolerance_ms",
    "arm_to_dispatch_max_ms",
    "control_turn_required",
    "segment_start_grace_seconds",
    "control_adapter",
    "required_capabilities",
    "interrupt_thresholds",
}
ALLOWED_INTERRUPT_THRESHOLD_FIELDS = {"tool_calls", "runtime_seconds"}
ALLOWED_VALIDATION_LINEAGE_FIELDS = {
    "root_packet_id",
    "parent_packet_id",
    "attempt",
}
ALLOWED_ESCALATION_TRIGGER_FIELDS = {
    "scope_ambiguity",
    "architecture_ambiguity",
    "security_ambiguity",
    "policy_ambiguity",
    "soft_limit",
    "hard_limit",
    "compaction",
}
ALLOWED_RETURN_CONTRACT_FIELDS = {
    "allowed_statuses",
    "required_fields",
    "realignment_required_fields",
}
ALLOWED_COMMAND_CONTRACT_FIELDS = {
    "required",
    "wrapper",
    "spec_schema",
    "result_schema",
    "modes",
    "typed_source_required_for",
    "complex_command_action",
    "construction_failure",
    "quarantine_failures",
}
ALLOWED_RETURN_FIELDS = {
    "return_type",
    "version",
    "packet_id",
    "bead_id",
    "session_id",
    "segment_id",
    "status",
    "requested_model",
    "actual_model",
    "attestation_source",
    "attestation_status",
    "completed_evidence",
    "files_touched",
    "mutation_state",
    "commands_run",
    "validation",
    "decision_required",
    "bounded_options",
    "recommendation",
    "remaining_scope",
    "usage",
    "residual_risks",
    *DISPOSITION_FIELDS,
}
ALLOWED_RETURN_USAGE_FIELDS = {
    "tool_calls",
    "elapsed_seconds",
    "context_compactions",
    "full_suite_runs",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "cached_input_tokens",
    "reasoning_tokens",
}

ACTION_CLASSES = {
    "read",
    "write",
    "test",
    "publish",
    "network",
    "control",
    "unknown",
}
PACKET_V3_PHASES = {
    "review",
    "implementation",
    "validation",
    "publish/report/admin",
}
ALLOWED_PACKET_V3_FIELDS = ALLOWED_PACKET_FIELDS | {
    "experimental",
    "phase",
    "phase_contract",
    "recovery_contract",
    "lineage_contract",
}
ALLOWED_PHASE_CONTRACT_FIELDS = {
    "phase",
    "expected_artifact_class",
    "permitted_first_action_classes",
    "first_action_deadline_seconds",
    "mutation_deadline_seconds",
    "source_mutation_policy",
}


@dataclass(frozen=True)
class PhaseContract:
    phase: str
    expected_artifact_class: str
    permitted_first_action_classes: tuple[str, ...]
    first_action_deadline_seconds: int
    mutation_deadline_seconds: int | None
    source_mutation_policy: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "expected_artifact_class": self.expected_artifact_class,
            "permitted_first_action_classes": list(self.permitted_first_action_classes),
            "first_action_deadline_seconds": self.first_action_deadline_seconds,
            "mutation_deadline_seconds": self.mutation_deadline_seconds,
            "source_mutation_policy": self.source_mutation_policy,
        }


@dataclass(frozen=True)
class LineageContract:
    root_packet_id: str
    parent_packet_id: str | None
    attempt: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "root_packet_id": self.root_packet_id,
            "parent_packet_id": self.parent_packet_id,
            "attempt": self.attempt,
        }


@dataclass(frozen=True)
class RecoveryContract:
    enabled: bool = False
    autonomous_replay: bool = False
    max_retries: int = 0
    requires_fresh_session: bool = True
    incomplete_baseline_disables_replay: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "autonomous_replay": self.autonomous_replay,
            "max_retries": self.max_retries,
            "requires_fresh_session": self.requires_fresh_session,
            "incomplete_baseline_disables_replay": self.incomplete_baseline_disables_replay,
        }


PHASE_CONTRACTS: dict[str, PhaseContract] = {
    "review": PhaseContract("review", "review-report", ("read", "test"), 30, None, "no-source-mutation"),
    "implementation": PhaseContract("implementation", "implementation-patch", ("read",), 30, 900, "scoped-only"),
    "validation": PhaseContract("validation", "validation-report", ("read", "test"), 30, None, "no-source-mutation"),
    "publish/report/admin": PhaseContract("publish/report/admin", "publish-report", ("read", "publish", "control"), 30, None, "explicitly-authorized-only"),
}


def packet_v3_phase_contract(phase: str) -> dict[str, Any]:
    """Return a detached, JSON-compatible phase contract."""
    try:
        return PHASE_CONTRACTS[str(phase)].as_dict()
    except KeyError as exc:
        raise ValueError(f"unknown packet-v3 phase: {phase!r}") from exc


def validate_packet_v3_phase_contract(value: Any, *, phase: str | None = None) -> list[str]:
    if not isinstance(value, dict):
        return ["phase_contract must be an object"]
    errors = [f"phase_contract has unknown field(s): {', '.join(sorted(set(value) - ALLOWED_PHASE_CONTRACT_FIELDS))}"] if set(value) - ALLOWED_PHASE_CONTRACT_FIELDS else []
    selected = phase or value.get("phase")
    if selected not in PACKET_V3_PHASES:
        errors.append("phase_contract.phase is not a supported packet-v3 phase")
        return errors
    expected = PHASE_CONTRACTS[selected]
    if value != expected.as_dict():
        errors.append("phase_contract must match the frozen packet-v3 phase contract")
    return errors


def packet_v3_lineage_contract(packet_id: str, *, root_packet_id: str | None = None, parent_packet_id: str | None = None, attempt: int = 0) -> dict[str, Any]:
    root = root_packet_id or packet_id
    if attempt not in {0, 1}:
        raise ValueError("packet-v3 lineage attempt must be 0 or 1")
    if attempt == 0 and parent_packet_id is not None:
        raise ValueError("packet-v3 attempt 0 cannot have a parent")
    if attempt == 1 and (not parent_packet_id or parent_packet_id == packet_id):
        raise ValueError("packet-v3 attempt 1 requires a distinct parent")
    return LineageContract(root, parent_packet_id, attempt).as_dict()


def packet_v3_recovery_contract() -> dict[str, Any]:
    return RecoveryContract().as_dict()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def canonical_argument_hash(arguments: Any) -> str:
    return hashlib.sha256(_canonical_json(arguments).encode("utf-8")).hexdigest()


_SECRET_KEY = re.compile(r"(token|secret|password|passwd|api[_-]?key|authorization|credential)", re.I)
_SECRET_VALUE = re.compile(r"(?i)(bearer\s+|(?:token|password|secret|api[_-]?key)=)([^\s,;]+)")


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): ("<redacted>" if _SECRET_KEY.search(str(key)) else _redact(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        return _SECRET_VALUE.sub(lambda match: f"{match.group(1)}<redacted>", value)
    return value


def _argument_value(payload: Mapping[str, Any]) -> Any:
    for key in ("arguments", "input", "args", "command", "cmd"):
        if key not in payload:
            continue
        value = payload[key]
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
        return value
    return {}


def _command_from_arguments(arguments: Any) -> str:
    if isinstance(arguments, str):
        return arguments.strip()
    if isinstance(arguments, Mapping):
        for key in ("command", "cmd", "code", "input"):
            value = arguments.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def classify_action(tool: Any, command: str = "", arguments: Any = None) -> str:
    haystack = f"{tool or ''} {command}".lower()
    if any(word in haystack for word in ("publish", "git push", "release")):
        return "publish"
    if any(word in haystack for word in ("curl", "wget", "http", "web", "network")):
        return "network"
    if any(word in haystack for word in ("supervis", "interrupt", "control", "close", "wait")):
        return "control"
    if any(word in haystack for word in ("apply_patch", "write", "edit", "mkdir", "touch", "rm ", "mv ", "cp ")):
        return "write"
    if any(word in haystack for word in ("pytest", "unittest", "compileall", " test", "check", "validate")):
        return "test"
    if any(word in haystack for word in ("cat", "rg", "grep", "sed", "find", "ls", "git status", "git diff", "git show", "read")):
        return "read"
    return "unknown"


def _target_paths(command: str, arguments: Any) -> list[str]:
    text = command or ""
    if not text and isinstance(arguments, Mapping):
        text = _command_from_arguments(arguments)
    try:
        tokens = shlex.split(text)
    except ValueError:
        return []
    result: list[str] = []
    for token in tokens:
        if token.startswith(("-", "$", "http://", "https://")):
            continue
        if "/" in token or token.startswith((".", "~")) or "." in token:
            clean = token.strip("'\"")
            if clean and clean not in result and not clean.startswith("<"):
                result.append(clean)
    return sorted(result)


def _event_items(record: Any) -> list[dict[str, Any]]:
    if not isinstance(record, Mapping):
        return []
    candidates: list[Any] = []
    for key in ("response_item", "response_items", "items"):
        if key in record:
            candidates.append(record[key])
    if record.get("type") == "response_item":
        candidates.append(record.get("payload"))
    candidates.append(record)
    items: list[dict[str, Any]] = []
    for value in candidates:
        if isinstance(value, Mapping):
            items.append(dict(value))
        elif isinstance(value, list):
            items.extend(dict(item) for item in value if isinstance(item, Mapping))
    return items


def _timestamp(record: Mapping[str, Any], item: Mapping[str, Any]) -> str | None:
    for source in (item, record):
        for key in ("timestamp", "created_at", "createdAt", "time"):
            value = source.get(key)
            if isinstance(value, (str, int, float)):
                return str(value)
    return None


def normalize_action_receipts(records: list[Mapping[str, Any]], *, segment_id: str | None = None) -> list[dict[str, Any]]:
    """Normalize tool calls and outputs into deterministic fail-closed receipts."""
    calls: dict[str, dict[str, Any]] = {}
    outputs: dict[str, list[dict[str, Any]]] = {}
    events: list[tuple[int, Mapping[str, Any], dict[str, Any]]] = []
    for record_index, record in enumerate(records):
        for item_index, item in enumerate(_event_items(record)):
            item_type = str(item.get("type") or item.get("kind") or "").lower()
            if item_type in {"function_call", "custom_tool_call", "tool_call"}:
                events.append((record_index * 1000 + item_index, record, item))
            elif item_type in {"function_call_output", "custom_tool_call_output", "tool_output", "function_output"}:
                events.append((record_index * 1000 + item_index, record, item))
    for order, record, item in events:
        item_type = str(item.get("type") or item.get("kind") or "").lower()
        call_id = str(item.get("call_id") or item.get("callId") or item.get("id") or "").strip() or None
        if item_type.endswith("output") or item_type in {"tool_output", "function_output"}:
            if call_id:
                outputs.setdefault(call_id, []).append({"order": order, "record": record, "item": item})
            else:
                outputs.setdefault(f"__unpaired_{order}", []).append({"order": order, "record": record, "item": item})
            continue
        tool = str(item.get("name") or item.get("tool") or item.get("tool_name") or "unknown")
        arguments = _argument_value(item)
        command = _command_from_arguments(arguments)
        calls[call_id or f"__anonymous_{order}"] = {
            "order": order,
            "record": record,
            "item": item,
            "tool": tool,
            "arguments": arguments,
            "command": command,
        }
    receipts: list[dict[str, Any]] = []
    for key, call in sorted(calls.items(), key=lambda pair: (pair[1]["order"], pair[0])):
        call_id = None if key.startswith("__anonymous_") else key
        paired = outputs.get(key, [])
        output = paired[0] if paired else None
        output_item = output["item"] if output else None
        exit_code = output_item.get("exit_code") if isinstance(output_item, Mapping) else None
        if not isinstance(exit_code, int):
            exit_code = 0 if output and not output_item.get("error") else (1 if output and output_item.get("error") else None)
        result_kind = "paired-success" if output and exit_code == 0 else "paired-failure" if output else "unpaired-call"
        receipts.append({
            "sequence": len(receipts),
            "timestamp": _timestamp(call["record"], call["item"]),
            "segment": segment_id or call["record"].get("segment_id") or call["record"].get("segment"),
            "tool": call["tool"],
            "call_id": call_id,
            "canonical_argument_hash": canonical_argument_hash(call["arguments"]),
            "redacted_command": _redact(call["command"]),
            "action_class": classify_action(call["tool"], call["command"], call["arguments"]),
            "determinable_target_paths": _target_paths(call["command"], call["arguments"]),
            "typed_result": {"kind": result_kind, "output_present": bool(output)},
            "exit_code": exit_code,
            "pairing_status": "paired" if output else "unpaired",
        })
    for key, entries in sorted(outputs.items(), key=lambda pair: pair[1][0]["order"]):
        if key in calls:
            continue
        for entry in entries:
            item = entry["item"]
            receipts.append({
                "sequence": len(receipts),
                "timestamp": _timestamp(entry["record"], item),
                "segment": segment_id or entry["record"].get("segment_id") or entry["record"].get("segment"),
                "tool": "unknown",
                "call_id": None if key.startswith("__unpaired_") else key,
                "canonical_argument_hash": canonical_argument_hash({}),
                "redacted_command": "",
                "action_class": "unknown",
                "determinable_target_paths": [],
                "typed_result": {"kind": "unpaired-output", "output_present": True},
                "exit_code": item.get("exit_code") if isinstance(item.get("exit_code"), int) else None,
                "pairing_status": "unpaired",
            })
    return receipts


# Short aliases make the evidence primitive discoverable without coupling
# callers to the original event-log vocabulary.
normalize_tool_events = normalize_action_receipts
build_action_receipts = normalize_action_receipts


def verify_first_action(
    receipt: Mapping[str, Any] | None,
    phase_contract: Mapping[str, Any],
    *,
    elapsed_seconds: float | int | None = None,
) -> dict[str, Any]:
    """Verify a first substantive action against an inert phase contract."""
    errors: list[str] = []
    if not isinstance(receipt, Mapping):
        errors.append("first substantive action is missing")
    else:
        action = receipt.get("action_class")
        permitted = phase_contract.get("permitted_first_action_classes", [])
        if action not in permitted:
            errors.append("first substantive action class is not permitted by phase contract")
        if receipt.get("action_class") == "unknown" or receipt.get("pairing_status") != "paired":
            errors.append("first substantive action is unknown or unpaired")
        deadline = phase_contract.get("first_action_deadline_seconds")
        if isinstance(deadline, (int, float)) and elapsed_seconds is not None and elapsed_seconds > deadline:
            errors.append("first substantive action missed its deadline")
    return {"eligible": not errors, "fail_closed": bool(errors), "errors": errors}


def verify_mutation_contract(
    phase_contract: Mapping[str, Any],
    *,
    mutation_observed: bool,
    elapsed_seconds: float | int | None = None,
    source_mutation_authorized: bool = True,
) -> dict[str, Any]:
    errors: list[str] = []
    policy = phase_contract.get("source_mutation_policy")
    if mutation_observed and policy == "no-source-mutation":
        errors.append("phase contract forbids source mutation")
    if mutation_observed and not source_mutation_authorized:
        errors.append("source mutation is not authorized")
    deadline = phase_contract.get("mutation_deadline_seconds")
    if mutation_observed and deadline is not None and elapsed_seconds is not None and elapsed_seconds > deadline:
        errors.append("mutation missed its deadline")
    return {"eligible": not errors, "fail_closed": bool(errors), "errors": errors}
ALLOWED_MUTATION_STATES = {"clean", "modified", "committed", "unknown"}
ALLOWED_ATTESTATION_STATUSES = {
    "trusted",
    "missing",
    "mismatch",
    "untrusted",
    "denied",
}
ALLOWED_ESCALATION_SOFT_LIMIT_FIELDS = {"distinct_soft_limits_required"}
ALLOWED_ESCALATION_HARD_LIMIT_FIELDS = {"any_hard_limit", "status"}
ALLOWED_ESCALATION_COMPACTION_FIELDS = {"any_compaction", "status"}


def verify_armed_supervision_state(
    state: Mapping[str, Any],
    packet: Mapping[str, Any],
    control_turn_id: str,
) -> list[str]:
    """Dispatch gate: the task prompt may only render against an armed supervisor.

    Binds the rendered prompt to one packet (by canonical hash), one armed
    supervision state, and one control turn, so a native worker cannot be
    dispatched without live supervision already in place.
    """
    errors: list[str] = []
    if str(state.get("result_type") or "") != "cwo-native-supervision-state":
        errors.append("supervision state has the wrong result_type")
    if state.get("status") != "armed":
        errors.append(f"supervision state status must be 'armed', found {state.get('status')!r}")
    expected_sha = artifact_hash(json.dumps(dict(packet), sort_keys=True))
    if state.get("packet_sha256") != expected_sha:
        errors.append("supervision state packet_sha256 does not match the packet being rendered")
    if state.get("packet_id") != packet.get("packet_id"):
        errors.append("supervision state packet_id does not match the packet")
    supplied = str(control_turn_id or "").strip()
    if not supplied:
        errors.append("control-turn-id must be non-empty")
    elif state.get("control_turn_id") != supplied:
        errors.append("control-turn-id does not match the armed supervision state")
    return errors


def verify_completed_supervision_state(
    state: Mapping[str, Any],
    packet: Mapping[str, Any],
) -> list[str]:
    """Acceptance gate: returns only validate against finalized supervision receipts."""
    errors: list[str] = []
    if str(state.get("result_type") or "") != "cwo-native-supervision-state":
        errors.append("supervision state has the wrong result_type")
    expected_sha = artifact_hash(json.dumps(dict(packet), sort_keys=True))
    if state.get("packet_sha256") != expected_sha:
        errors.append("supervision state packet_sha256 does not match the packet")
    status = state.get("status")
    if status not in {"completed", "closed", "control-failed"}:
        errors.append(f"supervision state is not finalized: status {status!r}")
    if not state.get("finalized_at"):
        errors.append("supervision state has no finalized_at receipt")
    return errors
