"""Contracts and deterministic evidence helpers for native worker execution.

The v3 structures in this module are intentionally inert.  They describe the
future evidence contract but do not authorize dispatch or replay.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from dataclasses import dataclass
from typing import Any, Mapping

from .native_disposition import DISPOSITION_FIELDS

ALLOWED_PACKET_FIELDS = {
    "packet_type",
    "version",
    "packet_id",
    "bead_id",
    "lane",
    "requested_model",
    "operative_routing",
    "session_policy",
    "tool_policy",
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
    "checked_command_sequence",
    "stage",
    "operative_dispatch_authorized",
    "release_requires",
    "precommit_receipt",
    "precommit_receipt_sha256",
    "release_evidence",
    "release_evidence_sha256",
}
STANDARD_TOOL_CALL_TYPES = frozenset(
    {
        "function_call",
        "functioncall",
        "custom_tool_call",
        "customtoolcall",
        "tool_call",
        "toolcall",
    }
)
_TOOL_EXIT_CODE_PATTERNS = (
    re.compile(
        r"\A(?:Chunk ID: [^\n]*\n)?"
        r"(?:Wall time: [^\n]*\n)?"
        r"Process exited with code (-?\d+)\n"
    ),
    re.compile(r"\AExit code:\s*(-?\d+)\n"),
)
_EXEC_COMMAND_INTERRUPTED_PATTERN = re.compile(
    r"\A(?:"
    r"aborted by user after (?:0|[1-9][0-9]*)(?:\.[0-9]+)?s"
    r"|Wall time: (?:0|[1-9][0-9]*)(?:\.[0-9]+)? seconds\n"
    r"aborted by user"
    r")\Z"
)
_EXEC_COMMAND_CREATE_PROCESS_ENOENT = (
    'exec_command failed: CreateProcess { message: "Rejected(\\"Failed to create '
    'unified exec process: No such file or directory (os error 2)\\")" }'
)
_APPLY_PATCH_FAILURE_PREFIX = "apply_patch verification failed:"
DIRECT_TOOL_TRANSPORT = "direct-tool-calls-v1"
NAMESPACED_EXEC_TOOL_TRANSPORT = "namespaced-exec-wrapper-v1"
_NAMESPACED_EXEC_SOURCE = re.compile(
    r"\Aconst\s+(?P<binding>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*"
    r"await\s+tools\.(?P<tool>apply_patch|exec_command|write_stdin)\("
    r"(?P<arguments>[\s\S]+)\);\s*"
    r"text\(JSON\.stringify\((?P=binding)\)\);\s*\Z"
)
_NAMESPACED_EXEC_ARGUMENT_FIELDS = {
    "exec_command": frozenset(
        {"cmd", "workdir", "tty", "yield_time_ms", "max_output_tokens"}
    ),
    "write_stdin": frozenset(
        {"session_id", "chars", "yield_time_ms", "max_output_tokens"}
    ),
}
_NAMESPACED_EXEC_RESULT_FIELDS = frozenset(
    {
        "chunk_id",
        "exit_code",
        "original_token_count",
        "output",
        "session_id",
        "wall_time_seconds",
    }
)
_NAMESPACED_EXEC_COMPLETED = re.compile(
    r"\AScript completed\nWall time "
    r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)? seconds\nOutput:\n(?P<body>[\s\S]*)\Z"
)
_NAMESPACED_EXEC_PATCH_VERIFICATION_FAILED = re.compile(
    r"\AScript failed\nWall time "
    r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)? seconds\nOutput:\n"
    r"Script error:\napply_patch verification failed: [^\r\n]+\Z"
)
ALLOWED_CHECKED_COMMAND_SEQUENCE_FIELDS = {
    "mode",
    "spec",
    "spec_path",
    "spec_sha256",
    "state_path",
    "output_path",
    "runner_argv",
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
    "replan",
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


def decode_namespaced_exec_source(source: Any) -> dict[str, Any]:
    """Decode the one-statement nested-tool grammar accepted by CWO.

    The wrapper is executable JavaScript, so accepting arbitrary source and
    searching it for ``tools.*`` would be unsafe.  This decoder accepts exactly
    one awaited nested call whose argument is JSON and exactly one JSON result
    projection.  Aliases, computed access, extra statements, comments, and
    non-JSON expressions fail closed.
    """

    if not isinstance(source, str) or not source:
        raise ValueError("namespaced-exec-source-invalid")
    match = _NAMESPACED_EXEC_SOURCE.fullmatch(source)
    if match is None:
        raise ValueError("namespaced-exec-source-grammar-invalid")
    tool = match.group("tool")
    raw_arguments = match.group("arguments")
    try:
        arguments = json.loads(raw_arguments)
    except json.JSONDecodeError as exc:
        raise ValueError("namespaced-exec-arguments-not-json") from exc
    if tool == "apply_patch":
        if not isinstance(arguments, str) or not arguments:
            raise ValueError("namespaced-exec-apply-patch-argument-invalid")
    else:
        if not isinstance(arguments, Mapping):
            raise ValueError("namespaced-exec-arguments-invalid")
        allowed = _NAMESPACED_EXEC_ARGUMENT_FIELDS[tool]
        if set(arguments) - allowed:
            raise ValueError("namespaced-exec-argument-fields-invalid")
        if tool == "exec_command":
            if "tty" in arguments and type(arguments["tty"]) is not bool:
                raise ValueError("namespaced-exec-tty-invalid")
            if (
                not isinstance(arguments.get("cmd"), str)
                or not arguments["cmd"]
                or not isinstance(arguments.get("workdir"), str)
                or not arguments["workdir"]
            ):
                raise ValueError("namespaced-exec-command-argument-invalid")
        else:
            session_id = arguments.get("session_id")
            if (
                isinstance(session_id, bool)
                or not isinstance(session_id, int)
                or session_id <= 0
            ):
                raise ValueError("namespaced-exec-session-id-invalid")
            if "chars" in arguments and not isinstance(arguments["chars"], str):
                raise ValueError("namespaced-exec-chars-invalid")
        for field in ("yield_time_ms", "max_output_tokens"):
            if field in arguments and (
                isinstance(arguments[field], bool)
                or not isinstance(arguments[field], int)
                or arguments[field] <= 0
            ):
                raise ValueError(f"namespaced-exec-{field}-invalid")
    return {
        "tool": tool,
        "arguments": arguments,
        "command": _command_from_arguments(arguments),
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
    }


def _command_from_arguments(arguments: Any) -> str:
    if isinstance(arguments, str):
        return arguments.strip()
    if isinstance(arguments, Mapping):
        for key in ("command", "cmd", "code", "input"):
            value = arguments.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _patch_target_paths(command: str, *, include_move_targets: bool) -> list[str]:
    """Extract paths only from the structural headers of an apply_patch body."""

    if not command.startswith("*** Begin Patch\n"):
        return []
    targets: list[str] = []
    primary_prefixes = (
        "*** Add File: ",
        "*** Delete File: ",
        "*** Update File: ",
    )
    for line in command.splitlines():
        prefix = next(
            (candidate for candidate in primary_prefixes if line.startswith(candidate)),
            None,
        )
        if prefix is not None:
            target = line[len(prefix) :].strip()
        elif include_move_targets and line.startswith("*** Move to: "):
            target = line[len("*** Move to: ") :].strip()
        else:
            continue
        if target and "\x00" not in target and target not in targets:
            targets.append(target)
    return sorted(targets)


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
    if any(
        word in haystack
        for word in (
            "cat",
            "rg",
            "grep",
            "sed",
            "find",
            "ls",
            "sha256sum",
            "git status",
            "git diff",
            "git show",
            "git rev-parse",
            "read",
        )
    ):
        return "read"
    return "unknown"


def _target_paths(command: str, arguments: Any) -> list[str]:
    text = command or ""
    if not text and isinstance(arguments, Mapping):
        text = _command_from_arguments(arguments)
    if text.startswith("*** Begin Patch\n"):
        return _patch_target_paths(text, include_move_targets=True)
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


def is_tool_call_item(item: Mapping[str, Any]) -> bool:
    """Recognize known and future call-shaped response items fail closed."""

    item_type = str(item.get("type") or item.get("kind") or "").lower()
    if not item_type or item_type.endswith("output"):
        return False
    return item_type in STANDARD_TOOL_CALL_TYPES or (
        item_type.endswith("_call") or item_type.endswith("call")
    )


def is_tool_output_item(item: Mapping[str, Any]) -> bool:
    item_type = str(item.get("type") or item.get("kind") or "").lower()
    return item_type in {
        "function_call_output",
        "custom_tool_call_output",
        "tool_output",
        "function_output",
    } or item_type.endswith("_call_output") or item_type.endswith("calloutput")


def trusted_tool_name(item: Mapping[str, Any]) -> str:
    """Return a tool identity that special call transports cannot spoof."""

    item_type = str(item.get("type") or item.get("kind") or "").lower()
    if item_type not in STANDARD_TOOL_CALL_TYPES:
        return item_type or "unknown"
    return str(
        item.get("name")
        or item.get("tool")
        or item.get("tool_name")
        or "unknown"
    )


def _output_text(item: Mapping[str, Any] | None) -> str:
    if not isinstance(item, Mapping):
        return ""
    output = item.get("output")
    if isinstance(output, str):
        return output
    if isinstance(output, list) and all(
        isinstance(part, Mapping)
        and part.get("type") in {"input_text", "inputText"}
        and isinstance(part.get("text"), str)
        and set(part) == {"type", "text"}
        for part in output
    ):
        return "".join(str(part["text"]) for part in output)
    return ""


def _paired_namespaced_exec_result(
    *,
    tool: str,
    output_item: Mapping[str, Any],
) -> tuple[str, int | None, bool, int | None]:
    """Classify an exact JSON-projected result from the exec wrapper."""

    rendered = _output_text(output_item)
    if (tool == "apply_patch"
            and _NAMESPACED_EXEC_PATCH_VERIFICATION_FAILED.fullmatch(rendered)):
        explicit_code, conflict = _explicit_output_exit_code(output_item)
        if conflict or explicit_code is not None or "exit_code" in output_item:
            return "paired-unknown", None, True, None
        # A terminal tool-input rejection precedes lifecycle emission. This
        # is not a process exit, and supplies no positive mutation evidence.
        return "paired-failure", None, False, None
    if (
        tool == "exec_command"
        and _EXEC_COMMAND_INTERRUPTED_PATTERN.fullmatch(rendered)
    ):
        return "paired-interrupted", None, False, None
    match = _NAMESPACED_EXEC_COMPLETED.fullmatch(rendered)
    if match is None:
        return "paired-unknown", None, False, None
    try:
        nested = json.loads(match.group("body"))
    except json.JSONDecodeError:
        return "paired-unknown", None, False, None
    if tool == "apply_patch":
        # The current nested freeform transport resolves successful patches to
        # an empty object.  Failure rejects the wrapper and therefore cannot
        # satisfy the exact completed envelope above.
        if nested == {}:
            return "paired-success", 0, False, None
        return "paired-unknown", None, False, None
    if not isinstance(nested, Mapping) or set(nested) - _NAMESPACED_EXEC_RESULT_FIELDS:
        return "paired-unknown", None, False, None
    nested_output = nested.get("output")
    if not isinstance(nested_output, str):
        return "paired-unknown", None, False, None
    operation_session_id = nested.get("session_id")
    if operation_session_id is not None and (
        isinstance(operation_session_id, bool)
        or not isinstance(operation_session_id, int)
        or operation_session_id <= 0
    ):
        return "paired-unknown", None, True, None
    exit_code = nested.get("exit_code")
    if isinstance(exit_code, bool) or (
        exit_code is not None and not isinstance(exit_code, int)
    ):
        return "paired-unknown", None, True, None
    if exit_code is None:
        if _EXEC_COMMAND_INTERRUPTED_PATTERN.fullmatch(nested_output):
            return "paired-interrupted", None, False, None
        if tool in {"exec_command", "write_stdin"} and operation_session_id is not None:
            return "paired-pending", None, False, operation_session_id
        return "paired-unknown", None, False, None
    return (
        ("paired-success", exit_code, False, operation_session_id)
        if exit_code == 0
        else ("paired-failure", exit_code, False, operation_session_id)
    )


def _explicit_output_exit_code(
    item: Mapping[str, Any] | None,
) -> tuple[int | None, bool]:
    """Return an explicit/transport-bound exit code and conflict status."""

    if not isinstance(item, Mapping):
        return None, False
    observed: list[int] = []
    explicit = item.get("exit_code")
    if isinstance(explicit, int) and not isinstance(explicit, bool):
        observed.append(explicit)
    text = _output_text(item)
    observed.extend(
        int(match.group(1))
        for pattern in _TOOL_EXIT_CODE_PATTERNS
        for match in pattern.finditer(text)
    )
    error_present = item.get("error") not in (None, False, "")
    if error_present and 0 in observed:
        return None, True
    if len(set(observed)) > 1:
        return None, True
    if observed:
        return observed[0], False
    if error_present:
        return 1, False
    return None, False


def _patch_apply_events(
    records: list[Mapping[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    events: dict[str, list[dict[str, Any]]] = {}
    for record_index, record in enumerate(records):
        if record.get("type") != "event_msg":
            continue
        payload = record.get("payload")
        if not isinstance(payload, Mapping) or payload.get("type") != "patch_apply_end":
            continue
        call_id = str(
            payload.get("call_id") or payload.get("callId") or ""
        ).strip()
        call_id_present = bool(call_id)
        if not call_id:
            call_id = f"__missing_{record_index * 1000}"
        events.setdefault(call_id, []).append(
            {
                "order": record_index * 1000,
                "item": dict(payload),
                "turn_id": payload.get("turn_id") or payload.get("turnId"),
                "call_id_present": call_id_present,
            }
        )
    return events


def _paired_tool_result(
    *,
    tool: str,
    output_item: Mapping[str, Any],
    patch_events: list[Mapping[str, Any]],
) -> tuple[str, int | None, bool]:
    """Classify a paired result from bounded trusted transport grammar."""

    exit_code, transport_conflict = _explicit_output_exit_code(output_item)
    if transport_conflict:
        return "paired-unknown", None, True
    text = _output_text(output_item)
    if tool == "exec_command" and _EXEC_COMMAND_INTERRUPTED_PATTERN.fullmatch(text):
        if exit_code is not None:
            return "paired-unknown", None, True
        return "paired-interrupted", None, False
    if tool == "exec_command" and text == _EXEC_COMMAND_CREATE_PROCESS_ENOENT:
        if exit_code is not None:
            return "paired-unknown", None, True
        # This exact current-host transport response proves that unified exec
        # did not create a process.  Whether it is a recoverable workdir typo is
        # controller context, so the receipt records only the bounded input
        # error here and leaves final classification to native supervision.
        return "paired-input-error", None, False
    if tool == "apply_patch":
        failure_text = text.startswith(_APPLY_PATCH_FAILURE_PREFIX)
        if len(patch_events) > 1:
            return "paired-unknown", None, True
        if patch_events:
            event = patch_events[0].get("item")
            if not isinstance(event, Mapping):
                return "paired-unknown", None, True
            event_success = event.get("success")
            event_status = event.get("status")
            structured_success = (
                event_success is True and event_status == "completed"
            )
            structured_failure = (
                event_success is False
                or event_status in {"failed", "error", "cancelled"}
            )
            if structured_success and (
                failure_text or exit_code not in (None, 0)
            ):
                return "paired-unknown", None, True
            if structured_failure and exit_code == 0:
                return "paired-unknown", None, True
            if structured_success:
                return "paired-success", 0, False
            if structured_failure:
                return "paired-failure", exit_code or 1, False
            return "paired-unknown", exit_code, False
        if failure_text:
            if exit_code == 0:
                return "paired-unknown", None, True
            return "paired-failure", exit_code or 1, False
        if exit_code is not None and exit_code != 0:
            return "paired-failure", exit_code, False
        # Successful apply_patch evidence requires its matching structured event.
        return "paired-unknown", exit_code, False
    if exit_code is None:
        return "paired-unknown", None, False
    return (
        ("paired-success", exit_code, False)
        if exit_code == 0
        else ("paired-failure", exit_code, False)
    )


def normalize_action_receipts(
    records: list[Mapping[str, Any]],
    *,
    segment_id: str | None = None,
    tool_transport: str = DIRECT_TOOL_TRANSPORT,
    include_private_transport_evidence: bool = False,
) -> list[dict[str, Any]]:
    """Normalize tool calls and outputs into deterministic fail-closed receipts."""
    if tool_transport not in {
        DIRECT_TOOL_TRANSPORT,
        NAMESPACED_EXEC_TOOL_TRANSPORT,
    }:
        raise ValueError("native-tool-transport-invalid")
    if type(include_private_transport_evidence) is not bool:
        raise ValueError("native-private-transport-evidence-flag-invalid")
    calls: list[dict[str, Any]] = []
    call_id_counts: dict[str, int] = {}
    outputs: dict[str, list[dict[str, Any]]] = {}
    patch_events = _patch_apply_events(records)
    events: list[tuple[int, Mapping[str, Any], dict[str, Any]]] = []
    for record_index, record in enumerate(records):
        for item_index, item in enumerate(_event_items(record)):
            if is_tool_call_item(item):
                events.append((record_index * 1000 + item_index, record, item))
            elif is_tool_output_item(item):
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
        tool = trusted_tool_name(item)
        arguments = _argument_value(item)
        command = _command_from_arguments(arguments)
        namespaced = False
        if (
            tool_transport == NAMESPACED_EXEC_TOOL_TRANSPORT
            and item_type in {"custom_tool_call", "customtoolcall"}
            and tool == "exec"
        ):
            try:
                decoded = decode_namespaced_exec_source(item.get("input"))
            except ValueError:
                pass
            else:
                tool = str(decoded["tool"])
                arguments = decoded["arguments"]
                command = str(decoded["command"])
                namespaced = True
        call_key = call_id or f"__anonymous_{order}"
        call_id_counts[call_key] = call_id_counts.get(call_key, 0) + 1
        calls.append({
            "key": call_key,
            "order": order,
            "record": record,
            "item": item,
            "tool": tool,
            "arguments": arguments,
            "command": command,
            "namespaced": namespaced,
        })
    nested_patch_events: dict[str, list[dict[str, Any]]] = {}
    consumed_patch_events: set[tuple[str, int]] = set()
    candidate_events_by_call: dict[int, list[tuple[str, dict[str, Any]]]] = {}
    candidate_calls_by_event: dict[tuple[str, int], list[int]] = {}
    for call_index, call in enumerate(calls):
        if not call["namespaced"] or call["tool"] != "apply_patch":
            continue
        if call_id_counts[str(call["key"])] != 1:
            continue
        paired_outputs = outputs.get(str(call["key"]), [])
        if len(paired_outputs) > 1:
            continue
        output_order = (
            int(paired_outputs[0]["order"])
            if paired_outputs
            else None
        )
        expected_targets = {
            target.replace("\\", "/").removeprefix("./")
            for target in _patch_target_paths(
                str(call["command"]),
                include_move_targets=False,
            )
        }
        if not expected_targets:
            continue
        candidates: list[tuple[str, dict[str, Any]]] = []
        for event_key, entries in patch_events.items():
            if event_key in call_id_counts or len(entries) != 1:
                continue
            event = entries[0]
            if event.get("call_id_present") is not True:
                continue
            if event["order"] <= call["order"]:
                continue
            if output_order is not None and event["order"] >= output_order:
                continue
            if segment_id is not None and event.get("turn_id") != segment_id:
                continue
            item = event.get("item")
            changes = item.get("changes") if isinstance(item, Mapping) else None
            if not isinstance(changes, Mapping) or not changes:
                continue
            observed_targets = {
                str(target).replace("\\", "/") for target in changes
            }
            if any(
                not target
                or "\x00" in target
                or any(part in {".", ".."} for part in target.split("/"))
                for target in observed_targets
            ):
                continue
            if len(observed_targets) != len(expected_targets):
                continue
            target_matches = {
                expected: [
                    observed
                    for observed in observed_targets
                    if observed == expected or observed.endswith("/" + expected)
                ]
                for expected in expected_targets
            }
            if not all(len(matches) == 1 for matches in target_matches.values()):
                continue
            if len({matches[0] for matches in target_matches.values()}) != len(
                observed_targets
            ):
                continue
            candidates.append((event_key, event))
        candidate_events_by_call[call_index] = candidates
        for event_key, event in candidates:
            event_identity = (event_key, int(event["order"]))
            candidate_calls_by_event.setdefault(event_identity, []).append(
                call_index
            )
    for call_index, candidates in candidate_events_by_call.items():
        if len(candidates) != 1:
            continue
        event_key, event = candidates[0]
        event_identity = (event_key, int(event["order"]))
        if len(candidate_calls_by_event.get(event_identity, [])) != 1:
            continue
        call_key = str(calls[call_index]["key"])
        nested_patch_events[call_key] = [event]
        consumed_patch_events.add(event_identity)
    receipts: list[dict[str, Any]] = []
    for call in sorted(
        calls,
        key=lambda item: (item["order"], item["key"]),
    ):
        key = str(call["key"])
        call_id = None if key.startswith("__anonymous_") else key
        paired = outputs.get(key, [])
        output = paired[0] if paired else None
        associated_nested_patch_events = nested_patch_events.get(key, [])
        all_patch_events = patch_events.get(key, []) + associated_nested_patch_events
        valid_patch_events = (
            [
                event
                for event in all_patch_events
                if output is not None
                and call["order"] < event["order"] < output["order"]
                and (
                    segment_id is None
                    or event.get("turn_id") == segment_id
                )
            ]
            if call["tool"] == "apply_patch"
            else []
        )
        pending_nested_patch_event = bool(
            call["namespaced"]
            and call["tool"] == "apply_patch"
            and output is None
            and len(associated_nested_patch_events) == 1
            and len(all_patch_events) == 1
        )
        pending_direct_patch_event = bool(
            not call["namespaced"]
            and call["tool"] == "apply_patch"
            and output is None
            and len(all_patch_events) == 1
            and all_patch_events[0]["order"] > call["order"]
            and (
                segment_id is None
                or all_patch_events[0].get("turn_id") == segment_id
            )
        )
        invalid_patch_event = bool(
            all_patch_events
            and (
                call["tool"] != "apply_patch"
                or (
                    len(valid_patch_events) != len(all_patch_events)
                    and not pending_nested_patch_event
                    and not pending_direct_patch_event
                )
            )
        )
        ambiguous = (
            call_id_counts[key] > 1
            or len(paired) > 1
            or len(valid_patch_events) > 1
            or invalid_patch_event
        )
        output_item = output["item"] if output else None
        result_conflict = False
        operation_session_id = None
        if ambiguous:
            result_kind = "ambiguous-call-or-output-cardinality"
            exit_code = None
        elif pending_direct_patch_event:
            # Direct apply_patch writes its descriptor-bound lifecycle event
            # immediately before the matching custom_tool_call_output.  That
            # valid in-progress split is pending, not ambiguous.  If the turn
            # becomes terminal before the output arrives, the boundary
            # summarizer still converts paired-pending into a fail-closed
            # telemetry anomaly.
            result_kind = "paired-pending"
            exit_code = None
        elif isinstance(output_item, Mapping):
            if call["namespaced"]:
                result_kind, exit_code, result_conflict, operation_session_id = (
                    _paired_namespaced_exec_result(
                        tool=str(call["tool"]),
                        output_item=output_item,
                    )
                )
                if call["tool"] == "apply_patch":
                    verification_rejection = (
                        result_kind == "paired-failure" and exit_code is None
                        and operation_session_id is None
                        and _NAMESPACED_EXEC_PATCH_VERIFICATION_FAILED.fullmatch(_output_text(output_item)) is not None
                    )
                    nested_success = (
                        len(valid_patch_events) == 1
                        and valid_patch_events[0].get("item", {}).get("success")
                        is True
                        and valid_patch_events[0].get("item", {}).get("status")
                        == "completed"
                    )
                    if verification_rejection:
                        # Absence must be real, not a malformed/misjoined event
                        # filtered out by target correlation. A strict wrapper
                        # has just one awaited tool, so any lifecycle emission
                        # inside its interval contradicts pre-mutation rejection.
                        event_in_interval = any(call["order"] < event["order"] < output["order"]
                            for events in patch_events.values() for event in events)
                        result_conflict = result_conflict or bool(all_patch_events) or event_in_interval
                    elif len(valid_patch_events) != 1 or (
                            result_kind == "paired-success" and not nested_success):
                        result_conflict = True
            else:
                result_kind, exit_code, result_conflict = _paired_tool_result(
                    tool=str(call["tool"]),
                    output_item=output_item,
                    patch_events=valid_patch_events,
                )
            if result_conflict:
                ambiguous = True
                result_kind = "ambiguous-call-or-output-cardinality"
                exit_code = None
        else:
            result_kind = "unpaired-call"
            exit_code = None
        argument_session_id = (
            call["arguments"].get("session_id")
            if call["tool"] == "write_stdin"
            and isinstance(call["arguments"], Mapping)
            else None
        )
        if (
            operation_session_id is not None
            and argument_session_id is not None
            and operation_session_id != argument_session_id
        ):
            ambiguous = True
            result_kind = "ambiguous-call-or-output-cardinality"
            exit_code = None
        receipts.append({
            "_source_order": call["order"],
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
            "pairing_status": (
                "ambiguous" if ambiguous else "paired" if output else "unpaired"
            ),
            "_operation_session_id": operation_session_id or argument_session_id,
            "_invocation_workdir_present": bool(
                call["tool"] == "exec_command"
                and isinstance(call["arguments"], Mapping)
                and "workdir" in call["arguments"]
            ),
            "_invocation_workdir": (
                call["arguments"].get("workdir")
                if call["tool"] == "exec_command"
                and isinstance(call["arguments"], Mapping)
                else None
            ),
        })
    call_keys = set(call_id_counts)
    for key, entries in sorted(outputs.items(), key=lambda pair: pair[1][0]["order"]):
        if key in call_keys:
            continue
        for entry in entries:
            item = entry["item"]
            receipts.append({
                "_source_order": entry["order"],
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
    for key, entries in sorted(
        patch_events.items(),
        key=lambda pair: pair[1][0]["order"],
    ):
        if key in call_keys:
            continue
        for entry in entries:
            if (key, int(entry["order"])) in consumed_patch_events:
                continue
            item = entry["item"]
            receipts.append(
                {
                    "_source_order": entry["order"],
                    "sequence": len(receipts),
                    "timestamp": None,
                    "segment": segment_id,
                    "tool": "unknown",
                    "call_id": key,
                    "canonical_argument_hash": canonical_argument_hash({}),
                    "redacted_command": "",
                    "action_class": "unknown",
                    "determinable_target_paths": [],
                    "typed_result": {
                        "kind": "unpaired-output",
                        "output_present": True,
                    },
                    "exit_code": (
                        0 if item.get("success") is True else 1
                        if item.get("success") is False
                        else None
                    ),
                    "pairing_status": "unpaired",
                }
            )
    receipts.sort(
        key=lambda item: (
            item["_source_order"],
            item["sequence"],
        )
    )
    for index, receipt in enumerate(receipts):
        if receipt.get("typed_result", {}).get("kind") != "paired-pending":
            continue
        session_id = receipt.get("_operation_session_id")
        resolved = any(
            later.get("tool") == "write_stdin"
            and later.get("_operation_session_id") == session_id
            and later.get("typed_result", {}).get("kind")
            in {"paired-success", "paired-failure"}
            for later in receipts[index + 1 :]
        )
        if resolved:
            receipt["typed_result"]["kind"] = "paired-deferred"
    for sequence, receipt in enumerate(receipts):
        receipt.pop("_source_order", None)
        receipt.pop("_operation_session_id", None)
        if not include_private_transport_evidence:
            receipt.pop("_invocation_workdir_present", None)
            receipt.pop("_invocation_workdir", None)
        receipt["sequence"] = sequence
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
