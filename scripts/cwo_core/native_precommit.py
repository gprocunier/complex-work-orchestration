from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import stat
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping

from .audit import record_audit_event
from .native_session import (
    COMPACTION_EVENT,
    SEGMENT_END_EVENT,
    SEGMENT_START_EVENT,
    _is_user_boundary_record,
    _normalize_event_msg,
    _normalize_response_items,
    _normalize_turn_context,
    _record_token_snapshot,
)
from .paths import cwo_temp_path, is_cwo_temp_path
from .policy import load_policy
from .util import atomic_write_text
from .workspace import capture_workspace_baseline, compare_workspace_baseline


STATE_TYPE = "cwo-native-precommit-state"
RECEIPT_TYPE = "cwo-native-precommit-receipt"
STATE_SCHEMA = "schemas/native-precommit-state.schema.json"
RECEIPT_SCHEMA = "schemas/native-precommit-receipt.schema.json"
VALIDATION_RULE_VERSION = "native-precommit-receipt:v2"
TRUSTED_ATTESTATION_SOURCE = "trusted-control-plane-session-metadata"
REQUIRED_MODEL = "gpt-5.3-codex-spark"
FINAL_STATE = "closed"
ACTIVE_STATES = {
    "created",
    "armed",
    "fit-dispatched",
    "completed",
    "interrupt-pending",
    "control-failed",
}
LIFECYCLE_STATES = ACTIVE_STATES | {FINAL_STATE}
FIT_DECISIONS = ("accept", "pm-realignment", "architect-realignment")
FIT_ESTIMATE_FIELDS = (
    "tool_calls_p50",
    "tool_calls_p90",
    "runtime_seconds_p50",
    "runtime_seconds_p90",
)
FIT_COMPLEXITY_DIMENSIONS = (
    "reasoning_uncertainty",
    "subsystem_coupling",
    "contract_risk",
    "diagnostic_uncertainty",
    "context_breadth",
    "validation_breadth",
)
FIT_ALLOWANCE_FIELDS = (
    "tool_calls_soft",
    "tool_calls_hard",
    "runtime_seconds_soft",
    "runtime_seconds_hard",
    "dispatch_soft_cap",
    "max_pm_replans",
    "max_architect_cycles",
    "max_compactions",
)
FIT_ALLOWANCE_METADATA_FIELDS = (
    "dispatch_soft_cap_action",
    "continuation_authority",
)
COMPLETION_ACTIONS = {"worker-completed", "interrupt-confirmed", "close-confirmed", "control-failed"}
HASH_RE = re.compile(r"^[0-9a-f]{64}$")

STATE_FIELDS = {
    "state_type",
    "version",
    "schema",
    "validation_rule_version",
    "state_id",
    "state_file",
    "packet_id",
    "work_unit_id",
    "bead_id",
    "attempt_nonce",
    "session_id",
    "session_file",
    "agent_id",
    "requested_model",
    "attested_model",
    "attestation_source",
    "work_plan_sha256",
    "fit_prompt",
    "fit_prompt_sha256",
    "workdir",
    "workspace_baseline",
    "baseline",
    "terminal",
    "owner_pid",
    "owner_identity",
    "control_execution_handle",
    "control_topology",
    "control_turn_id",
    "submission_id",
    "status",
    "decision",
    "reasons",
    "interrupt_requested",
    "closure_outcome",
    "poll_config",
    "polling",
    "observed",
    "final_response_sha256",
    "semantic_status",
    "fit_result",
    "control_receipts",
    "audit_event_hashes",
    "audit_file",
    "created_at",
    "updated_at",
    "closed_at",
}

RECEIPT_FIELDS = {
    "receipt_type",
    "version",
    "schema",
    "receipt_id",
    "state_id",
    "state_file",
    "state_sha256",
    "packet_id",
    "work_unit_id",
    "bead_id",
    "attempt_nonce",
    "session_id",
    "session_file",
    "agent_id",
    "requested_model",
    "attested_model",
    "attestation_source",
    "owner_identity",
    "control_execution_handle",
    "control_topology",
    "control_turn_id",
    "submission_id",
    "work_plan_sha256",
    "fit_prompt_sha256",
    "workspace_baseline",
    "baseline",
    "terminal",
    "token_telemetry",
    "observed",
    "polling",
    "control_receipts",
    "audit_event_hashes",
    "final_response_sha256",
    "semantic_status",
    "fit_result",
    "closure_outcome",
    "disposition",
    "validation_rule_version",
    "provenance",
    "accepting",
    "receipt_sha256",
}

BOUNDARY_FIELDS = {"record_count", "byte_offset", "boundary_sha256", "token_snapshot"}
TOKEN_FIELDS = {"availability", "baseline", "terminal", "delta"}
OBSERVED_FIELDS = {
    "function_calls",
    "custom_tool_calls",
    "context_compactions",
    "workspace_mutations",
    "workspace_evidence_sha256",
    "first_forbidden_event",
    "forbidden_events",
    "task_boundary_observed",
    "task_complete_observed",
}
POLLING_FIELDS = {
    "interval_ms",
    "lag_tolerance_ms",
    "armed_at",
    "dispatched_at",
    "first_successful_poll_at",
    "last_successful_poll_at",
    "poll_count",
    "max_gap_ms",
    "late_poll_count",
    "uninterrupted",
}
POLL_CONFIG_FIELDS = {"interval_ms", "lag_tolerance_ms", "arm_to_dispatch_max_ms"}
WORKSPACE_BASELINE_FIELDS = {"path", "sha256", "workdir"}
CONTROL_RECEIPT_FIELDS = {
    "action",
    "control_turn_id",
    "control_execution_handle",
    "submission_id",
    "at",
    "receipt_id",
}
PROVENANCE_FIELDS = {"issuer", "threat_model", "integrity"}
OWNER_IDENTITY_FIELDS = {
    "pid",
    "start_time_ticks",
    "process_group_id",
    "session_id",
    "boot_id_sha256",
    "execution_handle",
}
FIRST_FORBIDDEN_FIELDS = {"kind", "record_index"}
FIT_RESULT_FIELDS = {"decision", "estimates"}
ESTIMATE_FIELDS = set(FIT_ESTIMATE_FIELDS)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _iso_now(value: str | None = None) -> dt.datetime:
    if value:
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"invalid timestamp: {exc}") from exc
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    return dt.datetime.now(dt.timezone.utc)


def _iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _elapsed_ms(start: str, end: dt.datetime) -> int:
    return max(0, round((end - _iso_now(start)).total_seconds() * 1000))


def _require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _require_hash(value: Any, field: str) -> str:
    text = _require_string(value, field)
    if HASH_RE.fullmatch(text) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return text


def _require_exact_fields(value: Any, fields: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object")
    source = dict(value)
    missing = sorted(fields - set(source))
    unknown = sorted(set(source) - fields)
    details: list[str] = []
    if missing:
        details.append("missing " + ", ".join(missing))
    if unknown:
        details.append("unknown " + ", ".join(unknown))
    if details:
        raise ValueError(f"{field} fields are invalid: " + "; ".join(details))
    return source


def _policy() -> dict[str, Any]:
    value = load_policy("native-worker-execution").get("precommit_supervision")
    required = {
        "version",
        "state_schema",
        "receipt_schema",
        "validation_rule_version",
        "required_model",
        "attestation_source",
        "poll_interval_ms",
        "poll_lag_tolerance_ms",
        "arm_to_dispatch_max_ms",
        "packet_stage",
        "operative_dispatch_authorized",
        "release_requires",
        "control_topology",
    }
    source = _require_exact_fields(value, required, "precommit_supervision policy")
    expected = {
        "version": 2,
        "state_schema": STATE_SCHEMA,
        "receipt_schema": RECEIPT_SCHEMA,
        "validation_rule_version": VALIDATION_RULE_VERSION,
        "required_model": REQUIRED_MODEL,
        "attestation_source": TRUSTED_ATTESTATION_SOURCE,
        "packet_stage": "precommit-validated",
        "operative_dispatch_authorized": False,
        "release_requires": "complex-work-orchestration-fsh.3",
        "control_topology": "single-host-process-v1",
    }
    for field, expected_value in expected.items():
        if source.get(field) != expected_value:
            raise ValueError(f"precommit_supervision.{field} must equal {expected_value!r}")
    for field, minimum in (
        ("poll_interval_ms", 100),
        ("poll_lag_tolerance_ms", 0),
        ("arm_to_dispatch_max_ms", 100),
    ):
        current = source.get(field)
        if isinstance(current, bool) or not isinstance(current, int) or current < minimum:
            raise ValueError(f"precommit_supervision.{field} must be an integer >= {minimum}")
    return source


def render_fit_prompt(work_plan: Mapping[str, Any]) -> str:
    plan = dict(work_plan)
    task_class = _require_string(plan.get("task_class"), "work_plan.task_class")
    work_sizing = load_policy("native-worker-execution").get("work_sizing")
    if not isinstance(work_sizing, Mapping):
        raise ValueError("native worker work_sizing policy is missing")
    enforcement = work_sizing.get("enforcement")
    if not isinstance(enforcement, Mapping):
        raise ValueError("native worker work_sizing enforcement policy is missing")
    foundation = enforcement.get("foundation-canary")
    if not isinstance(foundation, Mapping):
        raise ValueError("native worker foundation-canary policy is missing")
    task_classes = foundation.get("task_class_policy")
    if not isinstance(task_classes, Mapping) or task_class not in task_classes:
        raise ValueError("work_plan.task_class must match a configured task class")
    scores = plan.get("scores")
    if not isinstance(scores, Mapping) or set(scores) != set(FIT_COMPLEXITY_DIMENSIONS):
        raise ValueError("work_plan.scores must contain the exact sanitized complexity dimensions")
    dimensions: dict[str, int] = {}
    for key in FIT_COMPLEXITY_DIMENSIONS:
        value = scores[key]
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 3:
            raise ValueError("work_plan.scores must contain only integers from 0 through 3")
        dimensions[key] = value
    raw_allowance = plan.get("aggregate_allowance")
    allowed_allowance_fields = set(FIT_ALLOWANCE_FIELDS) | set(FIT_ALLOWANCE_METADATA_FIELDS)
    if not isinstance(raw_allowance, Mapping) or not set(raw_allowance).issubset(allowed_allowance_fields):
        raise ValueError("work_plan.aggregate_allowance contains an unrecognized field")
    allowance: dict[str, int] = {}
    for key in FIT_ALLOWANCE_FIELDS:
        if key not in raw_allowance:
            continue
        value = raw_allowance[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("work_plan.aggregate_allowance must contain only non-negative integers")
        allowance[key] = value
    if not {"tool_calls_hard", "runtime_seconds_hard"}.issubset(allowance):
        raise ValueError("work_plan.aggregate_allowance is missing required numeric hard limits")
    payload = {
        "request_type": "cwo-native-worker-fit-request",
        "version": 2,
        "work_plan_sha256": canonical_sha256(plan),
        "task_class": task_class,
        "complexity_dimensions": dimensions,
        "aggregate_allowance": allowance,
        "decision_vocabulary": list(FIT_DECISIONS),
        "required_numeric_fields": list(FIT_ESTIMATE_FIELDS),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"


def _secure_input_file(path_value: str | Path, label: str) -> Path:
    raw = Path(path_value).expanduser()
    if raw.is_symlink():
        raise ValueError(f"{label} must be a regular non-symlink file")
    path = raw.resolve()
    if not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    if path.stat().st_uid != os.getuid():
        raise ValueError(f"{label} must be owned by the current user")
    return path


def _secure_output_path(path_value: str | Path | None, *, packet_id: str, purpose: str) -> Path:
    if path_value is None:
        path = cwo_temp_path(f"{packet_id}-{purpose}.json", purpose="native-precommit")
    else:
        raw = Path(path_value).expanduser()
        if raw.is_symlink():
            raise ValueError(f"{purpose} artifact must not be a symlink")
        path = raw.resolve()
    if not is_cwo_temp_path(path):
        raise ValueError(f"{purpose} artifact must be under a CWO-owned temporary directory")
    if path.exists() and (path.is_symlink() or not path.is_file() or path.stat().st_uid != os.getuid()):
        raise ValueError(f"{purpose} artifact is not a current-user regular file")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.stat().st_uid != os.getuid():
        raise ValueError(f"{purpose} artifact directory must be owned by the current user")
    path.parent.chmod(0o700)
    return path


def _private_write(path: Path, value: Mapping[str, Any]) -> None:
    atomic_write_text(path, json.dumps(dict(value), indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600 or path.stat().st_uid != os.getuid():
        raise ValueError(f"could not enforce private artifact ownership for {path}")


def _state_sidecar(path: Path) -> Path:
    return path.with_name(path.name + ".sha256")


@contextmanager
def _state_lock(path_value: str | Path) -> Iterator[Path]:
    path = _secure_output_path(path_value, packet_id="state", purpose="state")
    lock_path = path.with_name(path.name + ".lock")
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise ValueError(f"precommit state lock must be a current-user regular non-symlink file: {exc}") from exc
    with os.fdopen(descriptor, "a+", encoding="utf-8") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ValueError("precommit state lock must be owned by the current user")
        os.fchmod(handle.fileno(), 0o600)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield path
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _write_state(path: Path, state: Mapping[str, Any]) -> None:
    errors = validate_precommit_state(state)
    if errors:
        raise ValueError("invalid precommit state: " + "; ".join(errors))
    _private_write(path, state)
    sidecar = _state_sidecar(path)
    atomic_write_text(sidecar, canonical_sha256(dict(state)) + "\n")
    sidecar.chmod(0o600)


def _load_state_unlocked(path: Path) -> tuple[Path, dict[str, Any]]:
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        expected = _state_sidecar(path).read_text(encoding="utf-8").strip()
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"precommit state is unreadable: {exc}") from exc
    errors = validate_precommit_state(state)
    if errors:
        raise ValueError("invalid precommit state: " + "; ".join(errors))
    if expected != canonical_sha256(state):
        raise ValueError("precommit state canonical hash sidecar mismatch")
    return path, state


def _load_state(path_value: str | Path) -> tuple[Path, dict[str, Any]]:
    with _state_lock(path_value) as path:
        return _load_state_unlocked(path)


def _token_snapshot(records: list[dict[str, Any]]) -> dict[str, int] | None:
    latest = None
    for record in records:
        snapshot = _record_token_snapshot(record)
        if snapshot is not None:
            latest = {key: int(value) for key, value in snapshot.items()}
    return latest


def _boundary(path: Path, session_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    raw = path.read_bytes()
    if not raw:
        raise ValueError("session file has no complete records")
    if not raw.endswith(b"\n"):
        raise ValueError("session file has a trailing partial record")
    records: list[dict[str, Any]] = []
    for number, line in enumerate(raw.splitlines(keepends=True), 1):
        if not line.strip():
            continue
        try:
            decoded = line.decode("utf-8")
            value = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"session record {number} is invalid: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"session record {number} is not an object")
        explicit = value.get("session_id")
        if isinstance(explicit, str) and explicit and explicit != session_id:
            raise ValueError("session identity changed inside JSONL boundary")
        if value.get("type") == "session_meta":
            payload = value.get("payload")
            if isinstance(payload, dict) and isinstance(payload.get("id"), str) and payload["id"] != session_id:
                raise ValueError("session_meta identity does not match requested session")
        records.append(value)
    if not records:
        raise ValueError("session file has no complete object records")
    identity_seen = any(
        record.get("session_id") == session_id
        or (
            record.get("type") == "session_meta"
            and isinstance(record.get("payload"), dict)
            and record["payload"].get("id") == session_id
        )
        for record in records
    )
    if not identity_seen:
        raise ValueError("trusted session identity is missing from JSONL boundary")
    return (
        {
            "record_count": len(records),
            "byte_offset": len(raw),
            "boundary_sha256": hashlib.sha256(raw).hexdigest(),
            "token_snapshot": _token_snapshot(records),
        },
        records,
    )


def _trusted_models(records: list[dict[str, Any]]) -> tuple[set[str], list[str]]:
    models: set[str] = set()
    errors: list[str] = []
    for record in records:
        context = _normalize_turn_context(record)
        if not isinstance(context, dict):
            continue
        model = context.get("model")
        if not isinstance(model, str) or not model.strip():
            continue
        source = context.get("attestation_source") or context.get("attestationSource")
        if source != TRUSTED_ATTESTATION_SOURCE:
            errors.append("model metadata is missing trusted control-plane attestation source")
            continue
        models.add(model.strip())
    return models, errors


def _verify_exact_attestation(records: list[dict[str, Any]], requested_model: str) -> None:
    models, errors = _trusted_models(records)
    if errors:
        raise ValueError(errors[0])
    if not models:
        raise ValueError("trusted control-plane model attestation is missing")
    if models != {requested_model}:
        raise ValueError("trusted control-plane model attestation does not exactly match requested model")


def _same_boundary(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> bool:
    return all(actual.get(field) == expected.get(field) for field in BOUNDARY_FIELDS)


def _prefix_is_intact(path: Path, baseline: Mapping[str, Any]) -> None:
    raw = path.read_bytes()
    offset = baseline.get("byte_offset")
    if not isinstance(offset, int) or offset < 0:
        raise ValueError("baseline byte offset is invalid")
    if len(raw) < offset:
        raise ValueError("session JSONL was truncated below the baseline byte offset")
    if hashlib.sha256(raw[:offset]).hexdigest() != baseline.get("boundary_sha256"):
        raise ValueError("session JSONL prefix was rewritten after baseline capture")


def _workspace_artifact(state_path: Path, packet_id: str, workdir: Path) -> dict[str, Any]:
    baseline = capture_workspace_baseline(workdir, allowed_paths=["."], include_untracked=True)
    if baseline.get("incomplete") or not baseline.get("baseline_complete"):
        raise ValueError("workspace baseline comparison is incomplete")
    path = state_path.with_name(f"{packet_id}-precommit-workspace-baseline.json")
    _private_write(path, baseline)
    return {"path": str(path), "sha256": canonical_sha256(baseline), "workdir": str(workdir)}


def _load_workspace_baseline(metadata: Mapping[str, Any]) -> dict[str, Any]:
    path = _secure_input_file(_require_string(metadata.get("path"), "workspace_baseline.path"), "workspace baseline")
    try:
        baseline = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"workspace baseline is unreadable: {exc}") from exc
    if not isinstance(baseline, dict) or canonical_sha256(baseline) != metadata.get("sha256"):
        raise ValueError("workspace baseline canonical hash mismatch")
    if baseline.get("incomplete") or not baseline.get("baseline_complete"):
        raise ValueError("workspace baseline is incomplete")
    return baseline


def _workspace_report(metadata: Mapping[str, Any]) -> dict[str, Any]:
    before = _load_workspace_baseline(metadata)
    caps = before.get("caps") if isinstance(before.get("caps"), dict) else {}
    after = capture_workspace_baseline(
        Path(str(before.get("cwd"))),
        allowed_paths=["."],
        include_untracked=True,
        max_files=int(caps.get("max_files", 10000)),
        max_bytes=int(caps.get("max_bytes", 50_000_000)),
        max_seconds=float(caps.get("max_seconds", 5.0)),
    )
    report = compare_workspace_baseline(before, after, allowed_paths=["."])
    if report.get("incomplete"):
        raise ValueError("workspace comparison failed or is incomplete")
    return report


def _registry_root() -> Path:
    configured = os.environ.get("CWO_PRECOMMIT_REGISTRY_ROOT")
    path = Path(configured).expanduser() if configured else Path("/tmp/cwo-native-precommit-v1")
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("precommit registry root must be an absolute non-symlink path")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.stat().st_uid != os.getuid():
        raise ValueError("precommit registry root must be owned by the current user")
    path.chmod(0o700)
    return path.resolve()


@contextmanager
def _registry_lock() -> Iterator[Path]:
    root = _registry_root()
    lock_path = root / "registry.lock"
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield root
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _load_json_default(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"precommit registry is unreadable: {exc}") from exc


def _registry_write(path: Path, value: Any) -> None:
    atomic_write_text(path, json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    path.chmod(0o600)


def _process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _boot_id_sha256() -> str:
    try:
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError(f"control-plane boot identity is unavailable: {exc}") from exc
    if not boot_id:
        raise ValueError("control-plane boot identity is empty")
    return _text_sha256(boot_id)


def _process_stat_identity(pid: int) -> tuple[int, int, int]:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"control-plane process identity is unavailable: {exc}") from exc
    close = raw.rfind(")")
    if close < 0:
        raise ValueError("control-plane process identity record is malformed")
    fields = raw[close + 1 :].split()
    if len(fields) <= 19:
        raise ValueError("control-plane process identity record is incomplete")
    try:
        process_group_id = int(fields[2])
        session_id = int(fields[3])
        start_time_ticks = int(fields[19])
    except ValueError as exc:
        raise ValueError("control-plane process identity record is malformed") from exc
    if min(process_group_id, session_id, start_time_ticks) <= 0:
        raise ValueError("control-plane process identity values must be positive")
    return start_time_ticks, process_group_id, session_id


def _capture_owner_identity(pid: int, execution_handle: str) -> dict[str, Any]:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0 or not _process_alive(pid):
        raise ValueError("owner_pid must identify a live control-plane process")
    handle = _require_string(execution_handle, "control_execution_handle")
    start_time_ticks, process_group_id, session_id = _process_stat_identity(pid)
    return {
        "pid": pid,
        "start_time_ticks": start_time_ticks,
        "process_group_id": process_group_id,
        "session_id": session_id,
        "boot_id_sha256": _boot_id_sha256(),
        "execution_handle": handle,
    }


def _validate_owner_identity_shape(value: Any, field: str = "owner_identity") -> dict[str, Any]:
    identity = _require_exact_fields(value, OWNER_IDENTITY_FIELDS, field)
    for key in ("pid", "start_time_ticks", "process_group_id", "session_id"):
        current = identity.get(key)
        if isinstance(current, bool) or not isinstance(current, int) or current <= 0:
            raise ValueError(f"{field}.{key} must be a positive integer")
    _require_hash(identity.get("boot_id_sha256"), f"{field}.boot_id_sha256")
    _require_string(identity.get("execution_handle"), f"{field}.execution_handle")
    return identity


def _owner_identity_matches(value: Any) -> bool:
    try:
        expected = _validate_owner_identity_shape(value)
        actual = _capture_owner_identity(int(expected["pid"]), str(expected["execution_handle"]))
    except ValueError:
        return False
    return actual == expected


def _require_live_owner_identity(state: Mapping[str, Any]) -> None:
    identity = _validate_owner_identity_shape(state.get("owner_identity"))
    if state.get("owner_pid") != identity["pid"]:
        raise ValueError("owner_pid contradicts strong control-plane process identity")
    if state.get("control_execution_handle") != identity["execution_handle"]:
        raise ValueError("control execution handle contradicts strong process identity")
    if not _owner_identity_matches(identity):
        raise ValueError("control-plane process identity or topology changed")


def _paths_overlap(first: str, second: str) -> bool:
    left = Path(first).resolve()
    right = Path(second).resolve()
    return left == right or left in right.parents or right in left.parents


def _terminal_state_file(path_value: str) -> bool:
    try:
        path = _secure_output_path(path_value, packet_id="state", purpose="state")
        _, state = _load_state_unlocked(path)
    except ValueError:
        return False
    return state.get("status") == FINAL_STATE


def _register_identity_and_lease(state: Mapping[str, Any]) -> None:
    with _registry_lock() as root:
        identities_path = root / "identities.json"
        leases_path = root / "leases.json"
        identities = _load_json_default(identities_path, {"packet_ids": [], "attempt_nonces": []})
        leases = _load_json_default(leases_path, [])
        if not isinstance(identities, dict) or not isinstance(leases, list):
            raise ValueError("precommit registry shape is invalid")
        packet_ids = set(identities.get("packet_ids", []))
        nonces = set(identities.get("attempt_nonces", []))
        if state["packet_id"] in packet_ids:
            raise ValueError("duplicate precommit packet_id")
        if state["attempt_nonce"] in nonces:
            raise ValueError("duplicate precommit attempt nonce")
        retained: list[dict[str, Any]] = []
        for entry in leases:
            if not isinstance(entry, dict):
                raise ValueError("precommit lease registry is malformed")
            identity = entry.get("owner_identity")
            state_file = entry.get("state_file")
            if not isinstance(identity, dict) or not isinstance(state_file, str):
                raise ValueError("precommit lease registry is malformed")
            alive = _owner_identity_matches(identity)
            terminal = _terminal_state_file(state_file)
            if not alive and terminal:
                continue
            if not alive and not terminal:
                raise ValueError("stale precommit lease owner is dead but recorded state is non-terminal")
            retained.append(entry)
            if terminal:
                continue
            if entry.get("session_file") == state["session_file"]:
                raise ValueError("duplicate active precommit session")
            if _paths_overlap(str(entry.get("workdir")), str(state["workdir"])):
                raise ValueError("overlapping active precommit worktree lease")
        retained.append(
            {
                "state_id": state["state_id"],
                "state_file": state["state_file"],
                "packet_id": state["packet_id"],
                "attempt_nonce": state["attempt_nonce"],
                "session_file": state["session_file"],
                "workdir": state["workdir"],
                "owner_pid": state["owner_pid"],
                "owner_identity": dict(state["owner_identity"]),
                "control_execution_handle": state["control_execution_handle"],
                "control_topology": state["control_topology"],
                "status": state["status"],
            }
        )
        packet_ids.add(str(state["packet_id"]))
        nonces.add(str(state["attempt_nonce"]))
        _registry_write(
            identities_path,
            {"packet_ids": sorted(packet_ids), "attempt_nonces": sorted(nonces)},
        )
        _registry_write(leases_path, retained)


def _update_lease_state(state: Mapping[str, Any]) -> None:
    with _registry_lock() as root:
        path = root / "leases.json"
        entries = _load_json_default(path, [])
        if not isinstance(entries, list):
            raise ValueError("precommit lease registry is malformed")
        found = False
        for entry in entries:
            if isinstance(entry, dict) and entry.get("state_id") == state["state_id"]:
                entry["status"] = state["status"]
                found = True
        if not found:
            raise ValueError("precommit lease registry lost the active state binding")
        _registry_write(path, entries)


def _reservation_owner_is_current(identity: Any) -> bool:
    try:
        owner = _validate_owner_identity_shape(identity, "reservation.owner_identity")
    except ValueError:
        return False
    return owner["pid"] == os.getpid() and _owner_identity_matches(owner)


def reserve_precommit_receipt(receipt: Mapping[str, Any], packet_build_id: str) -> str:
    receipt_errors = validate_precommit_receipt(receipt, require_accepting=True)
    if receipt_errors:
        raise ValueError("invalid precommit receipt reservation: " + "; ".join(receipt_errors))
    receipt_sha256 = _require_hash(receipt.get("receipt_sha256"), "receipt_sha256")
    build_id = _require_string(packet_build_id, "packet_build_id")
    reservation_id = f"precommit-reservation-{uuid.uuid4().hex}"
    owner_identity = _capture_owner_identity(os.getpid(), reservation_id)
    with _registry_lock() as root:
        consumed_path = root / "consumed-receipts.json"
        reservations_path = root / "receipt-reservations.json"
        consumed = _load_json_default(consumed_path, {})
        reservations = _load_json_default(reservations_path, {})
        if not isinstance(consumed, dict) or not isinstance(reservations, dict):
            raise ValueError("precommit receipt registry is malformed")
        if receipt_sha256 in consumed:
            raise ValueError("precommit receipt replay detected")
        existing = reservations.get(receipt_sha256)
        if existing is not None:
            if not isinstance(existing, dict):
                raise ValueError("precommit receipt reservation registry is malformed")
            existing_owner = existing.get("owner_identity")
            if _owner_identity_matches(existing_owner):
                raise ValueError("precommit receipt already has an active packet-build reservation")
            state_file = existing.get("state_file")
            if not isinstance(state_file, str) or not _terminal_state_file(state_file):
                raise ValueError("stale receipt reservation owner is dead but state is non-terminal")
            del reservations[receipt_sha256]
        reservations[receipt_sha256] = {
            "reservation_id": reservation_id,
            "packet_build_id": build_id,
            "packet_id": receipt.get("packet_id"),
            "attempt_nonce": receipt.get("attempt_nonce"),
            "state_id": receipt.get("state_id"),
            "state_file": receipt.get("state_file"),
            "owner_identity": owner_identity,
        }
        _registry_write(reservations_path, reservations)
    return reservation_id


def commit_precommit_receipt_reservation(
    receipt: Mapping[str, Any],
    reservation_id: str,
    packet_sha256: str,
) -> None:
    receipt_sha256 = _require_hash(receipt.get("receipt_sha256"), "receipt_sha256")
    reservation = _require_string(reservation_id, "reservation_id")
    packet_hash = _require_hash(packet_sha256, "packet_sha256")
    with _registry_lock() as root:
        consumed_path = root / "consumed-receipts.json"
        reservations_path = root / "receipt-reservations.json"
        consumed = _load_json_default(consumed_path, {})
        reservations = _load_json_default(reservations_path, {})
        if not isinstance(consumed, dict) or not isinstance(reservations, dict):
            raise ValueError("precommit receipt registry is malformed")
        if receipt_sha256 in consumed:
            raise ValueError("precommit receipt replay detected")
        current = reservations.get(receipt_sha256)
        if not isinstance(current, dict) or current.get("reservation_id") != reservation:
            raise ValueError("precommit receipt reservation is missing or mismatched")
        if not _reservation_owner_is_current(current.get("owner_identity")):
            raise ValueError("precommit receipt reservation owner identity changed")
        for field in ("packet_id", "attempt_nonce", "state_id"):
            if current.get(field) != receipt.get(field):
                raise ValueError(f"precommit receipt reservation {field} binding changed")
        consumed[receipt_sha256] = {
            "packet_id": receipt.get("packet_id"),
            "attempt_nonce": receipt.get("attempt_nonce"),
            "state_id": receipt.get("state_id"),
            "reservation_id": reservation,
            "packet_build_id": current.get("packet_build_id"),
            "packet_sha256": packet_hash,
        }
        del reservations[receipt_sha256]
        _registry_write(consumed_path, consumed)
        _registry_write(reservations_path, reservations)


def release_precommit_receipt_reservation(receipt: Mapping[str, Any], reservation_id: str) -> None:
    receipt_sha256 = _require_hash(receipt.get("receipt_sha256"), "receipt_sha256")
    reservation = _require_string(reservation_id, "reservation_id")
    with _registry_lock() as root:
        path = root / "receipt-reservations.json"
        reservations = _load_json_default(path, {})
        if not isinstance(reservations, dict):
            raise ValueError("precommit receipt reservation registry is malformed")
        current = reservations.get(receipt_sha256)
        if not isinstance(current, dict) or current.get("reservation_id") != reservation:
            raise ValueError("precommit receipt reservation is missing or mismatched")
        if not _reservation_owner_is_current(current.get("owner_identity")):
            raise ValueError("precommit receipt reservation owner identity changed")
        del reservations[receipt_sha256]
        _registry_write(path, reservations)


def consume_precommit_receipt(receipt: Mapping[str, Any]) -> None:
    reservation_id = reserve_precommit_receipt(receipt, f"legacy-consume-{uuid.uuid4().hex}")
    commit_precommit_receipt_reservation(receipt, reservation_id, canonical_sha256(dict(receipt)))


def _audit(state: dict[str, Any], event_type: str) -> None:
    event = record_audit_event(
        {
            "event_type": event_type,
            "dispatch_id": state["state_id"],
            "bead_id": state["bead_id"],
            "requested_model": state["requested_model"],
            "actual_model": state["attested_model"],
            "status": state["status"],
            "decision": state["decision"],
            "prompt_sha256": state["fit_prompt_sha256"],
            "packet_sha256": state["work_plan_sha256"],
            "control_turn_id": state.get("control_turn_id"),
        },
        Path(state["audit_file"]),
    )
    state["audit_event_hashes"].append(event["event_hash"])


def _control_receipt(state: dict[str, Any], action: str, now: dt.datetime) -> None:
    state["control_receipts"].append(
        {
            "action": action,
            "control_turn_id": state["control_turn_id"],
            "control_execution_handle": state["control_execution_handle"],
            "submission_id": state.get("submission_id"),
            "at": _iso(now),
            "receipt_id": f"control-{uuid.uuid4().hex}",
        }
    )


def _require_control_turn(state: Mapping[str, Any], value: str) -> str:
    control_turn = _require_string(value, "control_turn_id")
    if state.get("control_turn_id") != control_turn:
        raise ValueError("control-turn identity does not match armed precommit state")
    return control_turn


def _set_control_failed(state: dict[str, Any], reason: str, now: dt.datetime) -> None:
    state["status"] = "control-failed"
    state["decision"] = "interrupt"
    state["interrupt_requested"] = True
    state["polling"]["uninterrupted"] = False
    state["reasons"] = list(dict.fromkeys([*state.get("reasons", []), reason]))
    state["updated_at"] = _iso(now)


def _record_poll(state: dict[str, Any], now: dt.datetime) -> None:
    polling = state["polling"]
    reference = polling.get("last_successful_poll_at") or polling.get("dispatched_at")
    if not reference:
        _set_control_failed(state, "missing-dispatch-timestamp-before-poll", now)
        return
    gap = _elapsed_ms(reference, now)
    polling["max_gap_ms"] = max(int(polling.get("max_gap_ms", 0)), gap)
    allowed = int(polling["interval_ms"]) + int(polling["lag_tolerance_ms"])
    if gap > allowed:
        polling["late_poll_count"] = int(polling["late_poll_count"]) + 1
        _set_control_failed(state, "precommit-polling-continuity-lost", now)
        return
    if polling.get("first_successful_poll_at") is None:
        polling["first_successful_poll_at"] = _iso(now)
    polling["last_successful_poll_at"] = _iso(now)
    polling["poll_count"] = int(polling["poll_count"]) + 1


def _response_text(item: Mapping[str, Any]) -> str | None:
    if item.get("type") != "message" or item.get("role") != "assistant":
        return None
    content = item.get("content")
    if isinstance(content, str):
        return content.strip() or None
    if isinstance(content, list):
        parts: list[str] = []
        for value in content:
            if isinstance(value, str):
                parts.append(value)
            elif isinstance(value, Mapping):
                text = value.get("text") or value.get("output_text")
                if isinstance(text, str):
                    parts.append(text)
        result = "".join(parts).strip()
        return result or None
    return None


def _final_response(records: list[dict[str, Any]]) -> str | None:
    result = None
    for record in records:
        for item in _normalize_response_items(record):
            text = _response_text(item)
            if text is not None:
                result = text
    return result


def parse_fit_result(raw: str) -> dict[str, Any]:
    try:
        source = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("fit response must be one JSON object") from exc
    if not isinstance(source, dict):
        raise ValueError("fit response must be one JSON object")
    allowed_top = {"decision", *FIT_ESTIMATE_FIELDS}
    if set(source) != allowed_top:
        raise ValueError("fit response fields must exactly match the decision and required p50/p90 fields")
    decision = source.get("decision")
    if decision not in FIT_DECISIONS:
        raise ValueError("fit response decision is outside the allowed vocabulary")
    estimates: dict[str, int] = {}
    for field in FIT_ESTIMATE_FIELDS:
        value = source.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"fit response {field} must be a positive integer")
        estimates[field] = value
    if estimates["tool_calls_p50"] > estimates["tool_calls_p90"]:
        raise ValueError("fit response tool_calls_p50 must be <= tool_calls_p90")
    if estimates["runtime_seconds_p50"] > estimates["runtime_seconds_p90"]:
        raise ValueError("fit response runtime_seconds_p50 must be <= runtime_seconds_p90")
    return {"decision": decision, "estimates": estimates}


def _activity(records: list[dict[str, Any]]) -> dict[str, Any]:
    function_calls = 0
    custom_tool_calls = 0
    compactions = 0
    first: dict[str, Any] | None = None
    forbidden: list[str] = []
    task_boundary = False
    task_complete = False
    for index, record in enumerate(records):
        event = _normalize_event_msg(record)
        if event == SEGMENT_START_EVENT or _is_user_boundary_record(record):
            task_boundary = True
        if event == SEGMENT_END_EVENT:
            task_complete = True
        if event == COMPACTION_EVENT:
            compactions += 1
            forbidden.append("context-compaction")
            first = first or {"kind": "context-compaction", "record_index": index}
        for item in _normalize_response_items(record):
            item_type = item.get("type")
            if item_type == "function_call":
                function_calls += 1
                forbidden.append("function-call")
                first = first or {"kind": "function-call", "record_index": index}
            elif item_type == "custom_tool_call":
                custom_tool_calls += 1
                forbidden.append("custom-tool-call")
                first = first or {"kind": "custom-tool-call", "record_index": index}
    return {
        "function_calls": function_calls,
        "custom_tool_calls": custom_tool_calls,
        "context_compactions": compactions,
        "first_forbidden_event": first,
        "forbidden_events": list(dict.fromkeys(forbidden)),
        "task_boundary_observed": task_boundary,
        "task_complete_observed": task_complete,
    }


def create_precommit_state(
    *,
    packet_id: str,
    work_plan: Mapping[str, Any],
    session_id: str,
    session_file: str | Path,
    agent_id: str,
    workdir: str | Path,
    state_file: str | Path | None = None,
    attempt_nonce: str | None = None,
    owner_pid: int | None = None,
    control_execution_handle: str | None = None,
    requested_model: str = REQUIRED_MODEL,
    audit_file: str | Path | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    policy = _policy()
    packet_id = _require_string(packet_id, "packet_id")
    session_id = _require_string(session_id, "session_id")
    agent_id = _require_string(agent_id, "agent_id")
    requested_model = _require_string(requested_model, "requested_model")
    if requested_model != policy["required_model"]:
        raise ValueError("precommit requested model must exactly match policy required_model")
    plan = dict(work_plan)
    work_unit_id = _require_string(plan.get("work_unit_id"), "work_plan.work_unit_id")
    bead_id = _require_string(plan.get("bead_id"), "work_plan.bead_id")
    if plan.get("requested_model") != requested_model:
        raise ValueError("work plan requested_model does not match precommit requested model")
    prompt = render_fit_prompt(plan)
    session_path = _secure_input_file(session_file, "session file")
    workspace = Path(workdir).expanduser().resolve()
    if not workspace.is_dir() or workspace.is_symlink():
        raise ValueError("workdir must be a regular directory")
    boundary, records = _boundary(session_path, session_id)
    _verify_exact_attestation(records, requested_model)
    nonce = attempt_nonce or f"attempt-{uuid.uuid4().hex}"
    nonce = _require_string(nonce, "attempt_nonce")
    state_path = _secure_output_path(state_file, packet_id=packet_id, purpose="state")
    audit_path = Path(audit_file).expanduser().resolve() if audit_file else state_path.with_name("precommit-audit.jsonl")
    if not is_cwo_temp_path(audit_path):
        raise ValueError("precommit audit file must be under a CWO-owned temporary directory")
    current = _iso_now(now)
    owner = owner_pid if owner_pid is not None else os.getppid()
    execution_handle = _require_string(
        control_execution_handle or f"control-execution-{uuid.uuid4().hex}",
        "control_execution_handle",
    )
    owner_identity = _capture_owner_identity(owner, execution_handle)
    state: dict[str, Any] = {
        "state_type": STATE_TYPE,
        "version": 2,
        "schema": STATE_SCHEMA,
        "validation_rule_version": VALIDATION_RULE_VERSION,
        "state_id": f"precommit-state-{uuid.uuid4().hex}",
        "state_file": str(state_path),
        "packet_id": packet_id,
        "work_unit_id": work_unit_id,
        "bead_id": bead_id,
        "attempt_nonce": nonce,
        "session_id": session_id,
        "session_file": str(session_path),
        "agent_id": agent_id,
        "requested_model": requested_model,
        "attested_model": requested_model,
        "attestation_source": TRUSTED_ATTESTATION_SOURCE,
        "work_plan_sha256": canonical_sha256(plan),
        "fit_prompt": prompt,
        "fit_prompt_sha256": _text_sha256(prompt),
        "workdir": str(workspace),
        "workspace_baseline": {},
        "baseline": boundary,
        "terminal": None,
        "owner_pid": owner,
        "owner_identity": owner_identity,
        "control_execution_handle": execution_handle,
        "control_topology": policy["control_topology"],
        "control_turn_id": None,
        "submission_id": None,
        "status": "created",
        "decision": "continue",
        "reasons": [],
        "interrupt_requested": False,
        "closure_outcome": None,
        "poll_config": {
            "interval_ms": policy["poll_interval_ms"],
            "lag_tolerance_ms": policy["poll_lag_tolerance_ms"],
            "arm_to_dispatch_max_ms": policy["arm_to_dispatch_max_ms"],
        },
        "polling": {
            "interval_ms": policy["poll_interval_ms"],
            "lag_tolerance_ms": policy["poll_lag_tolerance_ms"],
            "armed_at": None,
            "dispatched_at": None,
            "first_successful_poll_at": None,
            "last_successful_poll_at": None,
            "poll_count": 0,
            "max_gap_ms": 0,
            "late_poll_count": 0,
            "uninterrupted": True,
        },
        "observed": {
            "function_calls": 0,
            "custom_tool_calls": 0,
            "context_compactions": 0,
            "workspace_mutations": 0,
            "workspace_evidence_sha256": canonical_sha256({"mutation_detected": False}),
            "first_forbidden_event": None,
            "forbidden_events": [],
            "task_boundary_observed": False,
            "task_complete_observed": False,
        },
        "final_response_sha256": None,
        "semantic_status": "pending",
        "fit_result": None,
        "control_receipts": [],
        "audit_event_hashes": [],
        "audit_file": str(audit_path),
        "created_at": _iso(current),
        "updated_at": _iso(current),
        "closed_at": None,
    }
    with _state_lock(state_path) as locked_path:
        if locked_path.exists() or _state_sidecar(locked_path).exists():
            raise ValueError("precommit state artifact already exists")
        state["workspace_baseline"] = _workspace_artifact(locked_path, packet_id, workspace)
        _register_identity_and_lease(state)
        _audit(state, "native_precommit_created")
        _write_state(locked_path, state)
    result = dict(state)
    result["state_sha256"] = canonical_sha256(state)
    return result


def arm_precommit(state_file: str | Path, control_turn_id: str, *, now: str | None = None) -> dict[str, Any]:
    with _state_lock(state_file) as path:
        _, state = _load_state_unlocked(path)
        _require_live_owner_identity(state)
        if state["status"] != "created":
            raise ValueError("arm requires a created precommit state")
        boundary, records = _boundary(Path(state["session_file"]), state["session_id"])
        _prefix_is_intact(Path(state["session_file"]), state["baseline"])
        if not _same_boundary(state["baseline"], boundary):
            raise ValueError("session changed between precommit creation and arming")
        _verify_exact_attestation(records, state["requested_model"])
        report = _workspace_report(state["workspace_baseline"])
        if report.get("mutation_detected"):
            raise ValueError("workspace changed between precommit creation and arming")
        current = _iso_now(now)
        state["control_turn_id"] = _require_string(control_turn_id, "control_turn_id")
        state["status"] = "armed"
        state["polling"]["armed_at"] = _iso(current)
        state["updated_at"] = _iso(current)
        _control_receipt(state, "arm", current)
        _audit(state, "native_precommit_armed")
        _write_state(path, state)
        _update_lease_state(state)
        return state


def mark_fit_dispatched(
    state_file: str | Path,
    control_turn_id: str,
    submission_id: str,
    *,
    now: str | None = None,
) -> tuple[dict[str, Any], int]:
    with _state_lock(state_file) as path:
        _, state = _load_state_unlocked(path)
        _require_live_owner_identity(state)
        if state["status"] != "armed":
            raise ValueError("mark-dispatched requires an armed precommit state")
        current = _iso_now(now)
        supplied = _require_string(control_turn_id, "control_turn_id")
        state["submission_id"] = _require_string(submission_id, "submission_id")
        state["polling"]["dispatched_at"] = _iso(current)
        state["updated_at"] = _iso(current)
        if state["control_turn_id"] != supplied:
            _set_control_failed(state, "control-turn-mismatch-after-native-send", current)
        elif _elapsed_ms(state["polling"]["armed_at"], current) > state["poll_config"]["arm_to_dispatch_max_ms"]:
            _set_control_failed(state, "arm-to-dispatch-latency-exceeded", current)
        else:
            state["status"] = "fit-dispatched"
            _control_receipt(state, "native-send-input", current)
            _control_receipt(state, "dispatch-marked", current)
        _audit(state, "native_precommit_fit_dispatched")
        _write_state(path, state)
        _update_lease_state(state)
        return state, 2 if state["status"] == "control-failed" else 0


def check_precommit(
    state_file: str | Path,
    control_turn_id: str,
    *,
    now: str | None = None,
) -> tuple[dict[str, Any], int]:
    with _state_lock(state_file) as path:
        _, state = _load_state_unlocked(path)
        _require_live_owner_identity(state)
        try:
            _require_control_turn(state, control_turn_id)
        except ValueError:
            current = _iso_now(now)
            _set_control_failed(state, "control-turn-mismatch-during-precommit-monitoring", current)
            _audit(state, "native_precommit_control_lost")
            _write_state(path, state)
            _update_lease_state(state)
            return state, 2
        if state["status"] == FINAL_STATE:
            return state, 2 if state["closure_outcome"] != "completed" else 0
        if state["status"] not in {"fit-dispatched", "completed", "interrupt-pending", "control-failed"}:
            raise ValueError("check requires a fit-dispatched precommit state")
        current = _iso_now(now)
        if state["status"] == "fit-dispatched":
            _record_poll(state, current)
        try:
            session_path = Path(state["session_file"])
            _prefix_is_intact(session_path, state["baseline"])
            boundary, records = _boundary(session_path, state["session_id"])
            delta = records[int(state["baseline"]["record_count"]):]
            models, attestation_errors = _trusted_models(delta)
            if attestation_errors or (models and models != {state["requested_model"]}):
                raise ValueError("trusted model attestation changed during precommit fit")
            activity = _activity(delta)
            report = _workspace_report(state["workspace_baseline"])
            activity["workspace_mutations"] = len(report.get("mutations", []))
            activity["workspace_evidence_sha256"] = canonical_sha256(report)
            if report.get("mutation_detected"):
                activity["forbidden_events"].append("workspace-mutation")
                activity["first_forbidden_event"] = activity["first_forbidden_event"] or {
                    "kind": "workspace-mutation",
                    "record_index": None,
                }
            activity["forbidden_events"] = list(dict.fromkeys(activity["forbidden_events"]))
            state["observed"] = activity
            state["terminal"] = boundary
            forbidden = bool(activity["forbidden_events"])
            if state["status"] == "control-failed":
                state["interrupt_requested"] = True
            elif state["interrupt_requested"] or forbidden:
                state["status"] = "interrupt-pending"
                state["decision"] = "interrupt"
                state["interrupt_requested"] = True
                state["reasons"] = list(activity["forbidden_events"]) or state["reasons"]
            elif activity["task_complete_observed"]:
                response = _final_response(delta)
                state["final_response_sha256"] = _text_sha256(response or "")
                try:
                    state["fit_result"] = parse_fit_result(response or "")
                    state["semantic_status"] = "valid"
                    state["decision"] = state["fit_result"]["decision"]
                    state["reasons"] = []
                except ValueError as exc:
                    state["fit_result"] = None
                    state["semantic_status"] = "invalid"
                    state["decision"] = "reject"
                    state["reasons"] = [str(exc)]
                state["status"] = "completed"
            else:
                state["decision"] = "continue"
                state["reasons"] = []
        except ValueError as exc:
            _set_control_failed(state, str(exc), current)
        state["updated_at"] = _iso(current)
        _audit(state, "native_precommit_checked")
        _write_state(path, state)
        _update_lease_state(state)
        return state, 2 if state["status"] in {"interrupt-pending", "control-failed"} else 0


def finalize_precommit(
    state_file: str | Path,
    control_turn_id: str,
    control_action: str,
    *,
    now: str | None = None,
) -> dict[str, Any]:
    with _state_lock(state_file) as path:
        _, state = _load_state_unlocked(path)
        _require_live_owner_identity(state)
        try:
            _require_control_turn(state, control_turn_id)
        except ValueError:
            current = _iso_now(now)
            _set_control_failed(state, "control-turn-mismatch-during-precommit-finalization", current)
            _audit(state, "native_precommit_control_lost")
            _write_state(path, state)
            _update_lease_state(state)
            return state
        if control_action not in COMPLETION_ACTIONS:
            raise ValueError("unknown precommit control action")
        if state["status"] == FINAL_STATE:
            raise ValueError("closed precommit state cannot be reopened")
        current = _iso_now(now)
        if control_action == "worker-completed":
            if state["status"] != "completed" or state["interrupt_requested"]:
                raise ValueError("worker-completed requires unambiguous clean completion")
            _control_receipt(state, control_action, current)
        elif control_action == "interrupt-confirmed":
            if not state["interrupt_requested"] and state["status"] not in {"interrupt-pending", "control-failed"}:
                raise ValueError("interrupt-confirmed requires a prior interrupt request")
            state["interrupt_requested"] = True
            _control_receipt(state, control_action, current)
        elif control_action == "control-failed":
            _set_control_failed(state, "control-plane-reported-failure", current)
            _control_receipt(state, control_action, current)
        elif control_action == "close-confirmed":
            actions = [item.get("action") for item in state["control_receipts"]]
            if state["status"] == "completed" and not state["interrupt_requested"]:
                if "worker-completed" not in actions:
                    raise ValueError("clean close requires a worker-completed control receipt")
                outcome = "completed"
            elif state["status"] == "control-failed":
                if "interrupt-confirmed" not in actions:
                    raise ValueError("control-failed close requires interrupt confirmation")
                outcome = "control-failed"
            else:
                if "interrupt-confirmed" not in actions:
                    raise ValueError("interrupted close requires interrupt confirmation")
                outcome = "interrupted"
            _control_receipt(state, control_action, current)
            state["closure_outcome"] = outcome
            state["status"] = FINAL_STATE
            state["closed_at"] = _iso(current)
        state["updated_at"] = _iso(current)
        _audit(state, "native_precommit_control_receipt")
        _write_state(path, state)
        _update_lease_state(state)
        return state


def _token_telemetry(baseline: Mapping[str, Any], terminal: Mapping[str, Any]) -> dict[str, Any]:
    before = baseline.get("token_snapshot")
    after = terminal.get("token_snapshot")
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        return {"availability": "unavailable", "baseline": before, "terminal": after, "delta": None}
    keys = sorted(set(before) | set(after))
    delta = {key: max(0, int(after.get(key, 0)) - int(before.get(key, 0))) for key in keys}
    return {"availability": "available", "baseline": dict(before), "terminal": dict(after), "delta": delta}


def _expected_accepting(receipt: Mapping[str, Any]) -> bool:
    observed = receipt.get("observed") if isinstance(receipt.get("observed"), Mapping) else {}
    polling = receipt.get("polling") if isinstance(receipt.get("polling"), Mapping) else {}
    actions = [item.get("action") for item in receipt.get("control_receipts", []) if isinstance(item, Mapping)]
    deterministic = receipt.get("submission_id") == "deterministic-policy"
    controls = {"arm", "worker-completed", "close-confirmed"}
    if not deterministic:
        controls |= {"native-send-input", "dispatch-marked"}
    return (
        receipt.get("closure_outcome") == "completed"
        and receipt.get("semantic_status") == "valid"
        and receipt.get("attested_model") == receipt.get("requested_model") == REQUIRED_MODEL
        and receipt.get("attestation_source") == TRUSTED_ATTESTATION_SOURCE
        and observed.get("function_calls") == 0
        and observed.get("custom_tool_calls") == 0
        and observed.get("context_compactions") == 0
        and observed.get("workspace_mutations") == 0
        and observed.get("forbidden_events") == []
        and polling.get("uninterrupted") is True
        and polling.get("late_poll_count") == 0
        and (deterministic or int(polling.get("poll_count", 0)) >= 1)
        and controls.issubset(set(actions))
    )


def issue_precommit_receipt(
    state_file: str | Path,
    *,
    receipt_file: str | Path | None = None,
) -> dict[str, Any]:
    with _state_lock(state_file) as state_path:
        _, state = _load_state_unlocked(state_path)
        _require_live_owner_identity(state)
        return _issue_precommit_receipt_locked(state_path, state, receipt_file=receipt_file)


def _issue_precommit_receipt_locked(
    state_path: Path,
    state: dict[str, Any],
    *,
    receipt_file: str | Path | None = None,
) -> dict[str, Any]:
    if state["status"] != FINAL_STATE:
        raise ValueError("precommit receipt requires a closed state")
    current_boundary, _ = _boundary(Path(state["session_file"]), state["session_id"])
    terminal = state.get("terminal") or current_boundary
    if state["closure_outcome"] == "completed" and not _same_boundary(terminal, current_boundary):
        raise ValueError("session changed after clean completion and before receipt issuance")
    report = _workspace_report(state["workspace_baseline"])
    observed = dict(state["observed"])
    if report.get("mutation_detected"):
        observed["workspace_mutations"] = len(report.get("mutations", []))
        observed["workspace_evidence_sha256"] = canonical_sha256(report)
        observed["forbidden_events"] = list(dict.fromkeys([*observed["forbidden_events"], "workspace-mutation"]))
    receipt: dict[str, Any] = {
        "receipt_type": RECEIPT_TYPE,
        "version": 2,
        "schema": RECEIPT_SCHEMA,
        "receipt_id": f"precommit-receipt-{uuid.uuid4().hex}",
        "state_id": state["state_id"],
        "state_file": str(state_path),
        "state_sha256": canonical_sha256(state),
        "packet_id": state["packet_id"],
        "work_unit_id": state["work_unit_id"],
        "bead_id": state["bead_id"],
        "attempt_nonce": state["attempt_nonce"],
        "session_id": state["session_id"],
        "session_file": state["session_file"],
        "agent_id": state["agent_id"],
        "requested_model": state["requested_model"],
        "attested_model": state["attested_model"],
        "attestation_source": state["attestation_source"],
        "owner_identity": dict(state["owner_identity"]),
        "control_execution_handle": state["control_execution_handle"],
        "control_topology": state["control_topology"],
        "control_turn_id": state["control_turn_id"],
        "submission_id": state["submission_id"],
        "work_plan_sha256": state["work_plan_sha256"],
        "fit_prompt_sha256": state["fit_prompt_sha256"],
        "workspace_baseline": dict(state["workspace_baseline"]),
        "baseline": dict(state["baseline"]),
        "terminal": dict(terminal),
        "token_telemetry": _token_telemetry(state["baseline"], terminal),
        "observed": observed,
        "polling": dict(state["polling"]),
        "control_receipts": list(state["control_receipts"]),
        "audit_event_hashes": list(state["audit_event_hashes"]),
        "final_response_sha256": state["final_response_sha256"] or _text_sha256(""),
        "semantic_status": state["semantic_status"],
        "fit_result": state["fit_result"],
        "closure_outcome": state["closure_outcome"],
        "disposition": "accept" if state["closure_outcome"] == "completed" else "quarantine",
        "validation_rule_version": VALIDATION_RULE_VERSION,
        "provenance": {
            "issuer": "cwo-native-precommit-supervisor",
            "threat_model": "trusted-same-user-control-plane",
            "integrity": "canonical-sha256-private-artifacts-direct-provenance",
        },
        "accepting": False,
        "receipt_sha256": "",
    }
    receipt["accepting"] = _expected_accepting(receipt)
    if not receipt["accepting"] and receipt["disposition"] == "accept":
        receipt["disposition"] = "reject"
    receipt["receipt_sha256"] = canonical_sha256({key: value for key, value in receipt.items() if key != "receipt_sha256"})
    errors = validate_precommit_receipt(receipt)
    if errors:
        raise ValueError("invalid precommit receipt: " + "; ".join(errors))
    target = _secure_output_path(receipt_file, packet_id=state["packet_id"], purpose="receipt")
    _private_write(target, receipt)
    record_audit_event(
        {
            "event_type": "native_precommit_receipt_issued",
            "dispatch_id": state["state_id"],
            "bead_id": state["bead_id"],
            "packet_sha256": receipt["receipt_sha256"],
            "requested_model": state["requested_model"],
            "actual_model": state["attested_model"],
            "status": receipt["disposition"],
        },
        Path(state["audit_file"]),
    )
    result = dict(receipt)
    result["receipt_file"] = str(target)
    return result


def _validate_boundary_shape(value: Any, field: str) -> dict[str, Any]:
    boundary = _require_exact_fields(value, BOUNDARY_FIELDS, field)
    for key in ("record_count", "byte_offset"):
        current = boundary.get(key)
        if isinstance(current, bool) or not isinstance(current, int) or current < 1:
            raise ValueError(f"{field}.{key} must be a positive integer")
    _require_hash(boundary.get("boundary_sha256"), f"{field}.boundary_sha256")
    snapshot = boundary.get("token_snapshot")
    if snapshot is not None:
        if not isinstance(snapshot, Mapping):
            raise ValueError(f"{field}.token_snapshot must be an object or null")
        for key, current in snapshot.items():
            if not isinstance(key, str) or isinstance(current, bool) or not isinstance(current, int) or current < 0:
                raise ValueError(f"{field}.token_snapshot must contain non-negative integer values")
    return boundary


def _validate_fit_result_shape(value: Any, field: str) -> dict[str, Any]:
    result = _require_exact_fields(value, FIT_RESULT_FIELDS, field)
    if result.get("decision") not in FIT_DECISIONS:
        raise ValueError(f"{field}.decision is outside the allowed vocabulary")
    estimates = _require_exact_fields(result.get("estimates"), ESTIMATE_FIELDS, f"{field}.estimates")
    for key in FIT_ESTIMATE_FIELDS:
        current = estimates.get(key)
        if isinstance(current, bool) or not isinstance(current, int) or current < 1:
            raise ValueError(f"{field}.estimates.{key} must be a positive integer")
    if estimates["tool_calls_p50"] > estimates["tool_calls_p90"]:
        raise ValueError(f"{field} tool call quantiles are inconsistent")
    if estimates["runtime_seconds_p50"] > estimates["runtime_seconds_p90"]:
        raise ValueError(f"{field} runtime quantiles are inconsistent")
    return result


def _validate_observed_shape(value: Any, field: str) -> dict[str, Any]:
    observed = _require_exact_fields(value, OBSERVED_FIELDS, field)
    for key in ("function_calls", "custom_tool_calls", "context_compactions", "workspace_mutations"):
        current = observed.get(key)
        if isinstance(current, bool) or not isinstance(current, int) or current < 0:
            raise ValueError(f"{field}.{key} must be a non-negative integer")
    _require_hash(observed.get("workspace_evidence_sha256"), f"{field}.workspace_evidence_sha256")
    if observed.get("first_forbidden_event") is not None:
        first = _require_exact_fields(
            observed.get("first_forbidden_event"),
            FIRST_FORBIDDEN_FIELDS,
            f"{field}.first_forbidden_event",
        )
        _require_string(first.get("kind"), f"{field}.first_forbidden_event.kind")
        index = first.get("record_index")
        if index is not None and (isinstance(index, bool) or not isinstance(index, int) or index < 0):
            raise ValueError(f"{field}.first_forbidden_event.record_index must be a non-negative integer or null")
    if not isinstance(observed.get("forbidden_events"), list) or not all(
        isinstance(item, str) and item for item in observed["forbidden_events"]
    ):
        raise ValueError(f"{field}.forbidden_events must be a string list")
    for key in ("task_boundary_observed", "task_complete_observed"):
        if not isinstance(observed.get(key), bool):
            raise ValueError(f"{field}.{key} must be boolean")
    return observed


def _validate_polling_shape(value: Any, field: str) -> dict[str, Any]:
    polling = _require_exact_fields(value, POLLING_FIELDS, field)
    for key, minimum in (
        ("interval_ms", 100),
        ("lag_tolerance_ms", 0),
        ("poll_count", 0),
        ("max_gap_ms", 0),
        ("late_poll_count", 0),
    ):
        current = polling.get(key)
        if isinstance(current, bool) or not isinstance(current, int) or current < minimum:
            raise ValueError(f"{field}.{key} must be an integer >= {minimum}")
    for key in ("armed_at", "dispatched_at", "first_successful_poll_at", "last_successful_poll_at"):
        if polling.get(key) is not None and not isinstance(polling.get(key), str):
            raise ValueError(f"{field}.{key} must be a string or null")
    if not isinstance(polling.get("uninterrupted"), bool):
        raise ValueError(f"{field}.uninterrupted must be boolean")
    return polling


def _validate_control_receipts(
    value: Any,
    field: str,
    control_turn_id: Any,
    control_execution_handle: Any,
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    receipts: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        receipt = _require_exact_fields(item, CONTROL_RECEIPT_FIELDS, f"{field}[{index}]")
        for key in ("action", "control_turn_id", "control_execution_handle", "at", "receipt_id"):
            _require_string(receipt.get(key), f"{field}[{index}].{key}")
        if control_turn_id is not None and receipt.get("control_turn_id") != control_turn_id:
            raise ValueError(f"{field}[{index}].control_turn_id contradicts state binding")
        if receipt.get("control_execution_handle") != control_execution_handle:
            raise ValueError(f"{field}[{index}].control_execution_handle contradicts state binding")
        if receipt.get("submission_id") is not None and not isinstance(receipt.get("submission_id"), str):
            raise ValueError(f"{field}[{index}].submission_id must be a string or null")
        receipts.append(receipt)
    return receipts


def validate_precommit_state(value: Any) -> list[str]:
    errors: list[str] = []
    try:
        state = _require_exact_fields(value, STATE_FIELDS, "precommit state")
        if state.get("state_type") != STATE_TYPE or state.get("version") != 2 or state.get("schema") != STATE_SCHEMA:
            raise ValueError("precommit state type, version, or schema is invalid")
        if state.get("validation_rule_version") != VALIDATION_RULE_VERSION:
            raise ValueError("precommit state validation rule version is invalid")
        if state.get("status") not in LIFECYCLE_STATES:
            raise ValueError("precommit state lifecycle status is invalid")
        for field in (
            "state_id",
            "state_file",
            "packet_id",
            "work_unit_id",
            "bead_id",
            "attempt_nonce",
            "session_id",
            "session_file",
            "agent_id",
            "requested_model",
            "attested_model",
            "attestation_source",
            "control_execution_handle",
            "control_topology",
            "workdir",
            "audit_file",
            "created_at",
            "updated_at",
        ):
            _require_string(state.get(field), field)
        _require_hash(state.get("work_plan_sha256"), "work_plan_sha256")
        _require_hash(state.get("fit_prompt_sha256"), "fit_prompt_sha256")
        owner_identity = _validate_owner_identity_shape(state.get("owner_identity"))
        if state.get("owner_pid") != owner_identity["pid"]:
            raise ValueError("owner_pid contradicts owner_identity.pid")
        if state.get("control_execution_handle") != owner_identity["execution_handle"]:
            raise ValueError("control_execution_handle contradicts owner identity")
        if state.get("control_topology") != "single-host-process-v1":
            raise ValueError("control_topology is invalid")
        _validate_boundary_shape(state.get("baseline"), "baseline")
        if state.get("terminal") is not None:
            _validate_boundary_shape(state.get("terminal"), "terminal")
        workspace = _require_exact_fields(state.get("workspace_baseline"), WORKSPACE_BASELINE_FIELDS, "workspace_baseline")
        _require_string(workspace.get("path"), "workspace_baseline.path")
        _require_string(workspace.get("workdir"), "workspace_baseline.workdir")
        _require_hash(workspace.get("sha256"), "workspace_baseline.sha256")
        config = _require_exact_fields(state.get("poll_config"), POLL_CONFIG_FIELDS, "poll_config")
        for key in POLL_CONFIG_FIELDS:
            current = config.get(key)
            if isinstance(current, bool) or not isinstance(current, int) or current < 0:
                raise ValueError(f"poll_config.{key} must be a non-negative integer")
        _validate_observed_shape(state.get("observed"), "observed")
        _validate_polling_shape(state.get("polling"), "polling")
        if state.get("fit_result") is not None:
            _validate_fit_result_shape(state.get("fit_result"), "fit_result")
        _validate_control_receipts(
            state.get("control_receipts"),
            "control_receipts",
            state.get("control_turn_id"),
            state.get("control_execution_handle"),
        )
        audit_hashes = state.get("audit_event_hashes")
        if not isinstance(audit_hashes, list):
            raise ValueError("audit_event_hashes must be a list")
        for index, item in enumerate(audit_hashes):
            _require_hash(item, f"audit_event_hashes[{index}]")
        if state.get("status") == FINAL_STATE and state.get("closure_outcome") not in {"completed", "interrupted", "control-failed"}:
            raise ValueError("closed precommit state requires a closure_outcome")
    except ValueError as exc:
        errors.append(str(exc))
    return errors


def _receipt_hash(receipt: Mapping[str, Any]) -> str:
    return canonical_sha256({key: value for key, value in receipt.items() if key != "receipt_sha256"})


def _validate_fit_against_plan(receipt: Mapping[str, Any], work_plan: Mapping[str, Any]) -> None:
    if receipt.get("work_plan_sha256") != canonical_sha256(dict(work_plan)):
        raise ValueError("receipt work_plan_sha256 does not match current work plan")
    prompt = render_fit_prompt(work_plan)
    if receipt.get("fit_prompt_sha256") != _text_sha256(prompt):
        raise ValueError("receipt fit_prompt_sha256 does not match deterministic fit prompt")
    if receipt.get("work_unit_id") != work_plan.get("work_unit_id") or receipt.get("bead_id") != work_plan.get("bead_id"):
        raise ValueError("receipt work unit or Bead identity does not match current work plan")
    if receipt.get("requested_model") != work_plan.get("requested_model"):
        raise ValueError("receipt requested model does not match current work plan")
    fit_result = receipt.get("fit_result")
    if not isinstance(fit_result, Mapping):
        raise ValueError("receipt fit_result is missing")
    allowance = work_plan.get("aggregate_allowance")
    if not isinstance(allowance, Mapping):
        raise ValueError("work plan aggregate allowance is missing")
    estimates = fit_result.get("estimates")
    if not isinstance(estimates, Mapping):
        raise ValueError("receipt fit estimates are missing")
    if estimates.get("tool_calls_p90", 0) > allowance.get("tool_calls_hard", -1):
        raise ValueError("receipt fit tool_calls_p90 exceeds aggregate hard allowance")
    if estimates.get("runtime_seconds_p90", 0) > allowance.get("runtime_seconds_hard", -1):
        raise ValueError("receipt fit runtime_seconds_p90 exceeds aggregate hard allowance")


def validate_precommit_receipt(
    value: Any,
    work_plan: Mapping[str, Any] | None = None,
    *,
    expected_packet_id: str | None = None,
    live: bool = False,
    require_accepting: bool = False,
) -> list[str]:
    errors: list[str] = []
    try:
        receipt = _require_exact_fields(value, RECEIPT_FIELDS, "precommit receipt")
        if receipt.get("receipt_type") != RECEIPT_TYPE or receipt.get("version") != 2 or receipt.get("schema") != RECEIPT_SCHEMA:
            raise ValueError("precommit receipt type, version, or schema is invalid")
        if receipt.get("validation_rule_version") != VALIDATION_RULE_VERSION:
            raise ValueError("precommit receipt validation rule version is invalid")
        for field in (
            "receipt_id",
            "state_id",
            "state_file",
            "packet_id",
            "work_unit_id",
            "bead_id",
            "attempt_nonce",
            "session_id",
            "session_file",
            "agent_id",
            "requested_model",
            "attested_model",
            "attestation_source",
            "control_execution_handle",
            "control_topology",
            "control_turn_id",
            "submission_id",
            "closure_outcome",
            "disposition",
            "semantic_status",
        ):
            _require_string(receipt.get(field), field)
        for field in ("state_sha256", "work_plan_sha256", "fit_prompt_sha256", "final_response_sha256", "receipt_sha256"):
            _require_hash(receipt.get(field), field)
        owner_identity = _validate_owner_identity_shape(receipt.get("owner_identity"))
        if receipt.get("control_execution_handle") != owner_identity["execution_handle"]:
            raise ValueError("receipt control_execution_handle contradicts owner identity")
        if receipt.get("control_topology") != "single-host-process-v1":
            raise ValueError("receipt control_topology is invalid")
        if receipt["receipt_sha256"] != _receipt_hash(receipt):
            raise ValueError("precommit receipt canonical hash mismatch")
        baseline = _validate_boundary_shape(receipt.get("baseline"), "baseline")
        terminal = _validate_boundary_shape(receipt.get("terminal"), "terminal")
        workspace = _require_exact_fields(receipt.get("workspace_baseline"), WORKSPACE_BASELINE_FIELDS, "workspace_baseline")
        _require_string(workspace.get("path"), "workspace_baseline.path")
        _require_string(workspace.get("workdir"), "workspace_baseline.workdir")
        _require_hash(workspace.get("sha256"), "workspace_baseline.sha256")
        telemetry = _require_exact_fields(receipt.get("token_telemetry"), TOKEN_FIELDS, "token_telemetry")
        if telemetry.get("availability") not in {"available", "unavailable"}:
            raise ValueError("token_telemetry.availability must be available or unavailable")
        if telemetry["availability"] == "available" and not all(
            isinstance(telemetry.get(key), Mapping) for key in ("baseline", "terminal", "delta")
        ):
            raise ValueError("available token telemetry requires baseline, terminal, and delta objects")
        _validate_observed_shape(receipt.get("observed"), "observed")
        _validate_polling_shape(receipt.get("polling"), "polling")
        if receipt.get("fit_result") is not None:
            _validate_fit_result_shape(receipt.get("fit_result"), "fit_result")
        _validate_control_receipts(
            receipt.get("control_receipts"),
            "control_receipts",
            receipt.get("control_turn_id"),
            receipt.get("control_execution_handle"),
        )
        hashes = receipt.get("audit_event_hashes")
        if not isinstance(hashes, list) or not hashes:
            raise ValueError("audit_event_hashes must contain direct supervisor provenance")
        for index, item in enumerate(hashes):
            _require_hash(item, f"audit_event_hashes[{index}]")
        provenance = _require_exact_fields(receipt.get("provenance"), PROVENANCE_FIELDS, "provenance")
        expected_provenance = {
            "issuer": "cwo-native-precommit-supervisor",
            "threat_model": "trusted-same-user-control-plane",
            "integrity": "canonical-sha256-private-artifacts-direct-provenance",
        }
        if provenance != expected_provenance:
            raise ValueError("precommit receipt provenance is invalid")
        if expected_packet_id is not None and receipt["packet_id"] != expected_packet_id:
            raise ValueError("precommit receipt packet_id does not match preallocated packet_id")
        if receipt["requested_model"] != REQUIRED_MODEL or receipt["attested_model"] != REQUIRED_MODEL:
            raise ValueError("precommit receipt does not bind exact Spark model attestation")
        if receipt["attestation_source"] != TRUSTED_ATTESTATION_SOURCE:
            raise ValueError("precommit receipt attestation source is not trusted control-plane metadata")
        if receipt.get("accepting") is not _expected_accepting(receipt):
            raise ValueError("precommit receipt accepting flag contradicts validated evidence")
        if require_accepting and receipt.get("accepting") is not True:
            raise ValueError("precommit receipt is non-accepting")
        if receipt.get("accepting") is True and receipt.get("disposition") != "accept":
            raise ValueError("accepting precommit receipt must have disposition accept")
        if receipt.get("submission_id") == "deterministic-policy":
            if not _same_boundary(baseline, terminal):
                raise ValueError("deterministic receipt requires equal zero-length boundaries")
            observed = receipt["observed"]
            if any(observed.get(field) != 0 for field in ("function_calls", "custom_tool_calls", "context_compactions", "workspace_mutations")):
                raise ValueError("deterministic receipt requires explicit zero observed activity")
        if work_plan is not None:
            _validate_fit_against_plan(receipt, work_plan)
        if live:
            state_path, state = _load_state(receipt["state_file"])
            _ = state_path
            _require_live_owner_identity(state)
            if canonical_sha256(state) != receipt["state_sha256"]:
                raise ValueError("receipt state binding changed after issuance")
            for field in (
                "state_id",
                "packet_id",
                "attempt_nonce",
                "session_id",
                "agent_id",
                "control_turn_id",
                "control_execution_handle",
                "control_topology",
                "owner_identity",
                "submission_id",
            ):
                if state.get(field) != receipt.get(field):
                    raise ValueError(f"receipt {field} no longer matches bound state")
            session_path = _secure_input_file(receipt["session_file"], "receipt session file")
            _prefix_is_intact(session_path, baseline)
            current, records = _boundary(session_path, receipt["session_id"])
            _verify_exact_attestation(records, receipt["requested_model"])
            if not _same_boundary(terminal, current):
                raise ValueError("intervening session bytes or records invalidate precommit receipt")
            report = _workspace_report(receipt["workspace_baseline"])
            if report.get("mutation_detected"):
                raise ValueError("intervening workspace mutation invalidates precommit receipt")
    except (OSError, ValueError) as exc:
        errors.append(str(exc))
    return errors


def make_deterministic_receipt(
    *,
    packet_id: str,
    work_plan: Mapping[str, Any],
    session_id: str,
    session_file: str | Path,
    agent_id: str,
    workdir: str | Path,
    fit_result: Mapping[str, Any],
    control_turn_id: str,
    state_file: str | Path | None = None,
    receipt_file: str | Path | None = None,
    attempt_nonce: str | None = None,
    owner_pid: int | None = None,
    control_execution_handle: str | None = None,
    audit_file: str | Path | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    flat = {"decision": fit_result.get("decision")}
    estimates = fit_result.get("estimates")
    if not isinstance(estimates, Mapping):
        raise ValueError("deterministic fit_result estimates are missing")
    flat.update(estimates)
    normalized = parse_fit_result(json.dumps(flat, sort_keys=True))
    state_result = create_precommit_state(
        packet_id=packet_id,
        work_plan=work_plan,
        session_id=session_id,
        session_file=session_file,
        agent_id=agent_id,
        workdir=workdir,
        state_file=state_file,
        attempt_nonce=attempt_nonce,
        owner_pid=owner_pid,
        control_execution_handle=control_execution_handle,
        audit_file=audit_file,
        now=now,
    )
    with _state_lock(state_result["state_file"]) as state_path:
        _, state = _load_state_unlocked(state_path)
        _require_live_owner_identity(state)
        current = _iso_now(now)
        state["control_turn_id"] = _require_string(control_turn_id, "control_turn_id")
        state["submission_id"] = "deterministic-policy"
        state["status"] = "completed"
        state["decision"] = normalized["decision"]
        state["terminal"] = dict(state["baseline"])
        state["semantic_status"] = "valid"
        state["fit_result"] = normalized
        state["final_response_sha256"] = _text_sha256("")
        state["polling"]["armed_at"] = _iso(current)
        state["polling"]["dispatched_at"] = _iso(current)
        _control_receipt(state, "arm", current)
        _control_receipt(state, "deterministic-fit", current)
        _control_receipt(state, "worker-completed", current)
        _control_receipt(state, "close-confirmed", current)
        state["closure_outcome"] = "completed"
        state["status"] = FINAL_STATE
        state["closed_at"] = _iso(current)
        state["updated_at"] = _iso(current)
        _audit(state, "native_precommit_deterministic_closed")
        _write_state(state_path, state)
        _update_lease_state(state)
    receipt = issue_precommit_receipt(state_path, receipt_file=receipt_file)
    payload = {key: value for key, value in receipt.items() if key != "receipt_file"}
    errors = validate_precommit_receipt(
        payload,
        work_plan,
        expected_packet_id=packet_id,
        live=True,
        require_accepting=True,
    )
    if errors:
        raise ValueError("invalid deterministic precommit receipt: " + "; ".join(errors))
    return receipt
