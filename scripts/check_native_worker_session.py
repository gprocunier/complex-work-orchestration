#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import shlex
from pathlib import Path
from typing import Any

from cwo_core.native_disposition import derive_disposition

SCHEMA_PATH = "schemas/native-worker-session-check.schema.json"
REPO_POLICY = "policy/native-worker-execution.yaml"
SCHEMA_VERSION = 1
DEFAULT_REQUESTED_MODEL = "gpt-5.3-codex-spark"
SUPPORTED_BUDGET_PROFILES = (
    "implementation",
    "validation",
    "review",
    "publish-report-admin",
)
SEGMENT_START_EVENT = "task_started"
SEGMENT_END_EVENT = "task_complete"
COMPACTION_EVENT = "context_compacted"
TOKEN_FIELDS = {
    "input": {"input", "input_tokens"},
    "cached_input": {"cached_input", "cached_input_tokens"},
    "output": {"output", "output_tokens"},
    "reasoning": {"reasoning", "reasoning_tokens", "reasoning_output_tokens"},
    "total": {"total", "total_tokens"},
}


def _error(message: str, code: int = 1) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(code)


def _load_json_policy() -> dict[str, Any]:
    try:
        raw = Path(REPO_POLICY).read_text(encoding="utf-8")
    except OSError as exc:
        _error(f"unable to read policy {REPO_POLICY!r}: {exc}")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        _error(f"policy {REPO_POLICY!r} is not valid JSON: {exc}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check a native worker session log against native-worker policy budgets."
    )
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--requested-model", required=True)
    parser.add_argument("--budget-profile", required=True, choices=SUPPORTED_BUDGET_PROFILES)
    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument("--sessions-root", help="Directory containing session JSONL files.")
    source_group.add_argument(
        "--codex-home",
        help="Use <codex_home>/sessions for session discovery.",
    )
    source_group.add_argument(
        "--session-file",
        help="Explicit session JSONL file; skips root search.",
    )
    parser.add_argument(
        "--now",
        help="Optional ISO-8601 timestamp used for incomplete-segment closure.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    return parser.parse_args()


def _load_policy(profile: str) -> dict[str, Any]:
    policy = _load_json_policy()
    lane_budgets = policy.get("lane_budgets")
    if not isinstance(lane_budgets, dict):
        _error("policy lane_budgets missing")
    budget = lane_budgets.get(profile)
    if not isinstance(budget, dict):
        _error(f"budget profile {profile!r} is missing from policy")
    snapshot = {
        "tool_calls_soft": int(budget.get("tool_calls_soft", 0)),
        "tool_calls_hard": int(budget.get("tool_calls_hard", 0)),
        "runtime_seconds_soft": int(budget.get("runtime_seconds_soft", 0)),
        "runtime_seconds_hard": int(budget.get("runtime_seconds_hard", 0)),
        "max_compactions": int(budget.get("max_compactions", 0)),
        "max_full_suite_runs": int(budget.get("max_full_suite_runs", 0)),
    }
    return {
        "profile_name": profile,
        "snapshot": snapshot,
    }


def _sessions_root(codex_home: str | None = None) -> Path:
    if codex_home:
        return Path(codex_home).expanduser().resolve() / "sessions"
    codex_home = os.environ.get("CODEX_HOME")
    if codex_home:
        return Path(codex_home).expanduser().resolve() / "sessions"
    return Path.home() / ".codex" / "sessions"


def _iter_json_lines(path: Path, *, strict: bool = True):
    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        _error(f"unable to read {path}: {exc}", 1)
    for lineno, line in enumerate(raw_lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            yield lineno, json.loads(line)
        except json.JSONDecodeError as exc:
            if not strict:
                continue
            _error(f"{path}:{lineno} contains invalid JSON ({exc})", 1)


def _parse_iso_timestamp(raw: Any) -> dt.datetime:
    if raw is None:
        _error("missing timestamp")
    if isinstance(raw, (int, float)):
        return dt.datetime.fromtimestamp(raw, tz=dt.timezone.utc)
    if not isinstance(raw, str):
        _error(f"invalid timestamp type {type(raw)!r}")
    timestamp = raw.strip()
    if not timestamp:
        _error("empty timestamp")
    candidates = [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ]
    if timestamp.endswith("Z"):
        timestamp = timestamp[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(timestamp)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=dt.timezone.utc)
        return parsed
    except ValueError:
        pass
    for template in candidates:
        try:
            return dt.datetime.strptime(timestamp, template).replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
    _error(f"unparseable timestamp {raw!r}")


def _coerce_model(value: Any) -> str | None:
    if value is None or not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _loads_json_dict(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, str):
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, dict):
        return parsed
    return None


def _parse_token_count(payload: Any) -> dict[str, int] | None:
    if not isinstance(payload, dict):
        return None
    result = {
        "input": 0,
        "cached_input": 0,
        "output": 0,
        "reasoning": 0,
        "total": 0,
    }
    candidates: list[dict[str, Any]] = []
    saw_value = False
    if _coerce_model(payload.get("type")) == "token_count":
        info = payload.get("info")
        if isinstance(info, dict):
            total_token_usage = info.get("total_token_usage")
            if isinstance(total_token_usage, dict):
                source = total_token_usage
                for dst, aliases in TOKEN_FIELDS.items():
                    for alias in aliases:
                        candidate = source.get(alias)
                        if isinstance(candidate, int) and candidate >= 0:
                            result[dst] = candidate
                            saw_value = True
                            break
                if saw_value:
                    return result
            last_token_usage = info.get("last_token_usage")
            if isinstance(last_token_usage, dict):
                candidates.append(last_token_usage)
    raw = payload.get("token_count")
    if isinstance(raw, dict):
        candidates.append(raw)
    usage = payload.get("usage")
    if isinstance(usage, dict):
        candidates.append(usage)
    seen: set[str] = set()
    for source in candidates:
        if not isinstance(source, dict):
            continue
        for dst, aliases in TOKEN_FIELDS.items():
            if dst in seen:
                continue
            for alias in aliases:
                candidate = source.get(alias)
                if isinstance(candidate, int) and candidate >= 0:
                    result[dst] = candidate
                    saw_value = True
                    seen.add(dst)
                    break
    if not saw_value:
        return None
    return result


def _normalize_record_payload(record: Any) -> dict[str, Any] | None:
    if not isinstance(record, dict):
        return None
    payload = record.get("payload")
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, list):
        return None
    if isinstance(payload, str):
        return {"_raw": payload}
    return None


def _normalize_turn_context(record: dict[str, Any]) -> dict[str, Any] | None:
    if _coerce_model(record.get("type")) == "turn_context":
        return _normalize_record_payload(record)
    turn_context = record.get("turn_context")
    if isinstance(turn_context, dict):
        return turn_context
    return None


def _normalize_event_msg(record: dict[str, Any]) -> str | None:
    if _coerce_model(record.get("type")) == "event_msg":
        payload = _normalize_record_payload(record)
        if payload is not None:
            event_msg = (
                _coerce_model(payload.get("event_msg"))
                or _coerce_model(payload.get("event"))
                or _coerce_model(payload.get("type"))
            )
            if event_msg:
                return event_msg
            raw = payload.get("_raw")
            event_msg = _coerce_model(raw)
            if event_msg:
                return event_msg
    event_msg = _coerce_model(record.get("event_msg"))
    if event_msg:
        return event_msg
    return None


def _normalize_response_items(record: Any) -> list[dict[str, Any]]:
    if not isinstance(record, dict):
        return []
    items = None
    if _coerce_model(record.get("type")) == "response_item":
        items = record.get("payload")
    if items is None:
        items = record.get("response_item")
    if items is None:
        return []
    if isinstance(items, list):
        return [item for item in items if isinstance(item, dict)]
    if isinstance(items, dict):
        return [items]
    return []


def _extract_string_field(payload: Any, keys: tuple[str, ...]) -> str | None:
    if not isinstance(payload, dict):
        return None
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _extract_command(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    candidates: list[Any] = []
    for key in ("command", "cmd", "code", "input"):
        candidates.append(payload.get(key))
    args = payload.get("arguments")
    if isinstance(args, dict):
        candidates.append(args)
        candidates.append(args.get("command"))
        candidates.append(args.get("cmd"))
        candidates.append(_extract_string_field(args, ("code", "input")))
    elif isinstance(args, str):
        parsed = _loads_json_dict(args)
        candidates.append(parsed)
        if parsed is not None:
            candidates.append(parsed.get("command"))
            candidates.append(parsed.get("code"))
            candidates.append(parsed.get("cmd"))
            candidates.append(parsed.get("input"))
        candidates.append(args)
    for candidate in candidates:
        command = _extract_string_field(candidate, ("command", "cmd", "code", "input", "arguments"))
        if command:
            return command
        if isinstance(candidate, str):
            clean = candidate.strip()
            if clean:
                if clean.startswith("{") or clean.startswith("["):
                    parsed = _loads_json_dict(clean)
                    if parsed is not None:
                        command = _extract_string_field(
                            parsed, ("command", "cmd", "code", "input", "arguments")
                        )
                        if command:
                            return command
                return clean
    return None


def _is_full_suite_command(command: str) -> bool:
    try:
        args = shlex.split(command)
    except ValueError:
        return False
    if not args:
        return False
    interpreter = args[0].split("/")[-1]
    if interpreter not in {"python", "python3"}:
        return False
    try:
        m_index = args.index("-m")
    except ValueError:
        return False
    if m_index + 1 >= len(args) or args[m_index + 1] != "unittest":
        return False
    discover_index = -1
    for index in range(m_index + 2, len(args)):
        if args[index] == "discover":
            discover_index = index
            break
    if discover_index == -1:
        return False
    for index in range(discover_index + 1, len(args)):
        token = args[index]
        if token != "-s":
            continue
        if index + 1 >= len(args):
            continue
        if args[index + 1] == "tests":
            return True
    return False


def _record_token_snapshot(record: dict[str, Any]) -> dict[str, int] | None:
    record_type = _coerce_model(record.get("type"))
    if record_type == "event_msg":
        event_payload = _normalize_record_payload(record)
        if isinstance(event_payload, dict):
            token_snapshot = _parse_token_count(event_payload)
            if token_snapshot is not None:
                return token_snapshot
    turn_context = _normalize_turn_context(record)
    if isinstance(turn_context, dict):
        token_snapshot = _parse_token_count(turn_context)
        if token_snapshot is not None:
            return token_snapshot
    token_payload = _normalize_record_payload(record)
    if isinstance(token_payload, dict):
        return _parse_token_count(token_payload)
    return None


def _is_user_boundary_record(record: dict[str, Any]) -> bool:
    if not isinstance(record, dict):
        return False
    response_items = _normalize_response_items(record)
    if not response_items:
        return False
    boundary_payload = response_items[0]
    if not isinstance(boundary_payload, dict):
        return False
    if _coerce_model(boundary_payload.get("type")) != "message":
        return False
    if _coerce_model(boundary_payload.get("role")) != "user":
        return False
    return True


def _build_segment_snapshot() -> dict[str, Any]:
    return {
        "tool_calls": 0,
        "context_compactions": 0,
        "full_suite_runs": 0,
        "runtime_seconds": 0.0,
        "token_deltas": {
            "input": 0,
            "cached_input": 0,
            "output": 0,
            "reasoning": 0,
            "total": 0,
        },
        "models": [],
        "attested_model": None,
        "attestation_source": "untrusted",
        "status": "within-budget",
        "return_status": "within-budget",
        "soft_limit_reasons": [],
        "hard_stop_reasons": [],
        "records": 0,
        "session_disposition": "accepted",
        "artifact_disposition": "accepted",
        "artifact_validation": {
            "eligible": False,
            "max_attempts": 1,
            "attempts_used": 0,
            "outcome": "not-run",
            "reason": "pending segment evaluation",
        },
    }


def _segment_runtime_seconds(start: dt.datetime | None, end: dt.datetime) -> float:
    if start is None:
        return 0.0
    delta = end - start
    return max(0.0, delta.total_seconds())


def _close_segment(
    segment: dict[str, Any],
    budget: dict[str, Any],
    requested_model: str,
    start_tokens: dict[str, int],
    end_tokens: dict[str, int],
    segment_start: dt.datetime | None,
    end_ts: dt.datetime,
) -> dict[str, Any]:
    segment["runtime_seconds"] = _segment_runtime_seconds(segment_start, end_ts)
    segment["attested_model"] = segment["attested_model"] or (
        sorted(set(segment["models"]))[0] if segment["models"] else None
    )
    segment["token_deltas"] = {
        key: max(0, end_tokens[key] - start_tokens[key]) for key in start_tokens
    }
    return _finalize_segment(segment, budget, requested_model)


def _normalize_segment_model(
    record: dict[str, Any], segment: dict[str, Any]
) -> tuple[str | None, bool]:
    turn_context = _normalize_turn_context(record)
    model = None
    from_turn_context = False
    if isinstance(turn_context, dict):
        model = _coerce_model(turn_context.get("model"))
        if model is not None:
            from_turn_context = True
        if model is None:
            model = _coerce_model(turn_context.get("attested_model"))
    if model is None:
        return None, False
    if model is None:
        return None, False
    if isinstance(model, str):
        segment["models"].append(model)
    return model, from_turn_context


def _finalize_segment(
    segment: dict[str, Any],
    budget: dict[str, Any],
    requested_model: str,
) -> dict[str, Any]:
    soft_limits: set[str] = set()
    hard_limits: set[str] = set()
    missing_attestation = not segment["models"]
    mismatch = bool(segment["models"]) and any(
        model != requested_model for model in segment["models"]
    )
    if missing_attestation:
        hard_limits.add("missing-attestation")
        segment["return_status"] = "model-mismatch"
        segment["status"] = "model-mismatch"
    if mismatch:
        hard_limits.add("model-mismatch")
        segment["return_status"] = "model-mismatch"
        segment["status"] = "model-mismatch"
    if segment["tool_calls"] > budget["tool_calls_hard"]:
        hard_limits.add("tool_calls_hard")
    if segment["runtime_seconds"] > budget["runtime_seconds_hard"]:
        hard_limits.add("runtime_seconds_hard")
    if segment["context_compactions"] > budget["max_compactions"]:
        hard_limits.add("max_compactions")
    if segment["full_suite_runs"] > budget["max_full_suite_runs"]:
        hard_limits.add("max_full_suite_runs")

    if not hard_limits:
        if segment["tool_calls"] > budget["tool_calls_soft"]:
            soft_limits.add("tool_calls_soft")
        if segment["runtime_seconds"] > budget["runtime_seconds_soft"]:
            soft_limits.add("runtime_seconds_soft")

        if len(soft_limits) >= 2:
            segment["status"] = "needs-architect-realignment"
            segment["return_status"] = "needs-architect-realignment"
        elif len(soft_limits) == 1:
            segment["status"] = "soft-limit"
            segment["return_status"] = "soft-limit"
            segment["soft_limit_reasons"] = sorted(soft_limits)
        else:
            segment["status"] = "within-budget"
            segment["return_status"] = "within-budget"
            segment["soft_limit_reasons"] = []
    else:
        segment["status"] = "budget-exhausted" if segment["status"] != "model-mismatch" else "model-mismatch"
        segment["return_status"] = "budget-exhausted" if "model-mismatch" not in hard_limits and "missing-attestation" not in hard_limits else "model-mismatch"
        segment["hard_stop_reasons"] = sorted(hard_limits)
        segment["soft_limit_reasons"] = sorted(soft_limits)

        if not segment["hard_stop_reasons"] and segment["status"] != "model-mismatch":
            segment["hard_stop_reasons"] = []

    if not segment["soft_limit_reasons"] and segment["status"] not in {"model-mismatch", "needs-architect-realignment", "budget-exhausted"}:
        segment["soft_limit_reasons"] = sorted(soft_limits)

    if segment["status"] == "needs-architect-realignment":
        segment["hard_stop_reasons"] = []

    segment["models"] = sorted(set(segment["models"]))
    if segment["attested_model"] is None and segment["models"]:
        segment["attested_model"] = segment["models"][0]
    disposition = derive_disposition(
        status=segment["status"],
        requested_model=requested_model,
        actual_model=segment["attested_model"],
        usage={
            "tool_calls": segment["tool_calls"],
            "elapsed_seconds": segment["runtime_seconds"],
            "context_compactions": segment["context_compactions"],
            "full_suite_runs": segment["full_suite_runs"],
        },
        budget=budget,
    )
    segment.update(disposition)
    return segment


def _status_worst(worst: str, candidate: str) -> str:
    rank = {
        "within-budget": 0,
        "soft-limit": 1,
        "needs-architect-realignment": 2,
        "budget-exhausted": 3,
        "model-mismatch": 4,
    }
    return candidate if rank[candidate] > rank[worst] else worst


def _status_to_return_code(status: str) -> int:
    if status in {"model-mismatch", "budget-exhausted", "needs-architect-realignment"}:
        return 2
    if status in {"within-budget", "soft-limit", "unknown"}:
        return 0
    return 0


def find_session_file(
    session_id: str,
    sessions_root: Path,
    explicit: Path | None = None,
) -> Path:
    if explicit:
        if not explicit.is_file():
            _error(f"session file {explicit} is missing")
        matches = _session_id_matches(explicit, session_id)
        if not matches:
            _error(
                f"session id {session_id!r} not present in explicit session file {explicit}"
            )
        return explicit

    if not sessions_root.is_dir():
        _error(f"sessions root {sessions_root} is not a directory")
    candidates = [
        path
        for path in sorted(sessions_root.rglob("*.jsonl"))
        if path.is_file() and session_id in path.name and path.suffix == ".jsonl"
    ]
    if not candidates:
        for path in sorted(sessions_root.rglob("*.jsonl")):
            if not path.is_file():
                continue
            if _session_id_matches(path, session_id, strict=False):
                candidates.append(path)
    if not candidates:
        _error(f"missing session file for session id {session_id!r}")
    if len(candidates) > 1:
        _error(f"ambiguous session id {session_id!r} matches {len(candidates)} files")
    return candidates[0]


def _session_id_matches(path: Path, session_id: str, *, strict: bool = True) -> bool:
    for _, record in _iter_json_lines(path, strict=strict):
        if not isinstance(record, dict):
            continue
        current = record.get("session_id")
        if current == session_id:
            return True
        if _coerce_model(record.get("type")) == "session_meta":
            payload = _normalize_record_payload(record)
            if isinstance(payload, dict) and payload.get("id") == session_id:
                return True
    return False


def _evaluate_records(
    records: list[dict[str, Any]],
    budget: dict[str, Any],
    requested_model: str,
    now: dt.datetime | None,
) -> tuple[list[dict[str, Any]], dict[str, Any], str, dict[str, Any]]:
    if not records:
        _error("session has no records")
    segments: list[dict[str, Any]] = []
    has_explicit_segments = any(
        isinstance(record, dict)
        and _normalize_event_msg(record) == SEGMENT_START_EVENT
        for record in records
    )
    open_segment: dict[str, Any] | None = None
    segment_start: dt.datetime | None = None
    last_tokens = {"input": 0, "cached_input": 0, "output": 0, "reasoning": 0, "total": 0}
    segment_start_tokens = None
    previous_tokens = last_tokens.copy()
    previous_ts: dt.datetime | None = None
    for record in records:
        if not isinstance(record, dict):
            continue
        event_msg = _normalize_event_msg(record) or ""
        ts = _parse_iso_timestamp(record.get("timestamp"))
        token_snapshot = _record_token_snapshot(record)
        if token_snapshot is not None:
            last_tokens = token_snapshot

        is_user_boundary = not has_explicit_segments and _is_user_boundary_record(record)
        if is_user_boundary:
            if open_segment is not None:
                if previous_ts is None:
                    _error("user boundary encountered without previous record to close previous segment")
                open_segment = _close_segment(
                    open_segment,
                    budget,
                    requested_model,
                    segment_start_tokens or last_tokens,
                    previous_tokens,
                    segment_start,
                    previous_ts,
                )
                segments.append(open_segment)

            open_segment = _build_segment_snapshot()
            segment_start_tokens = last_tokens.copy()
            segment_start = ts
            model, from_turn_context = _normalize_segment_model(record, open_segment)
            if model and from_turn_context:
                open_segment["attestation_source"] = "turn_context"
            attestation_source = None
            turn_context = _normalize_turn_context(record)
            if isinstance(turn_context, dict):
                attestation_source = (
                    _coerce_model(turn_context.get("attestation_source"))
                    or _coerce_model(turn_context.get("attestationSource"))
                )
            if attestation_source and not from_turn_context:
                open_segment["attestation_source"] = attestation_source
            open_segment["records"] += 1
            previous_tokens = last_tokens
            previous_ts = ts
            continue

        if event_msg == SEGMENT_START_EVENT:
            if open_segment is not None and segment_start is not None:
                segments.append(
                    _close_segment(
                        open_segment,
                        budget,
                        requested_model,
                        segment_start_tokens,
                        previous_tokens,
                        segment_start,
                        previous_ts or ts,
                    )
                )
            open_segment = _build_segment_snapshot()
            segment_start_tokens = last_tokens.copy()
            segment_start = ts
            if event_msg:
                model, from_turn_context = _normalize_segment_model(record, open_segment)
                if model and from_turn_context:
                    open_segment["attestation_source"] = "turn_context"
            attestation_source = None
            turn_context = _normalize_turn_context(record)
            if isinstance(turn_context, dict):
                attestation_source = _coerce_model(turn_context.get("attestation_source")) or _coerce_model(
                    turn_context.get("attestationSource")
                )
            if attestation_source and not from_turn_context:
                open_segment["attestation_source"] = attestation_source
            open_segment["records"] += 1
            previous_tokens = last_tokens
            previous_ts = ts
            continue

        if open_segment is None:
            continue

        open_segment["records"] += 1
        model, from_turn_context = _normalize_segment_model(record, open_segment)
        if model is not None and from_turn_context:
            open_segment["attestation_source"] = "turn_context"

        turn_context = _normalize_turn_context(record)
        if isinstance(turn_context, dict):
            turn_source = _coerce_model(turn_context.get("attestation_source")) or _coerce_model(
                turn_context.get("attestationSource")
            )
            if turn_source and not from_turn_context:
                open_segment["attestation_source"] = turn_source

        for response_item in _normalize_response_items(record):
            rtype = response_item.get("type") or response_item.get("name")
            if isinstance(rtype, str) and rtype in {"function_call", "custom_tool_call"}:
                open_segment["tool_calls"] += 1
                command = _extract_command(response_item) or ""
                if _is_full_suite_command(command):
                    open_segment["full_suite_runs"] += 1
            elif event_msg == "response_event":
                if (
                    isinstance(response_item.get("name"), str)
                    and response_item.get("name") == "Shell"
                ):
                    command = _extract_command(response_item)
                    if _is_full_suite_command(command or ""):
                        open_segment["full_suite_runs"] += 1

        if event_msg == COMPACTION_EVENT:
            open_segment["context_compactions"] += 1

        if event_msg == SEGMENT_END_EVENT:
            segments.append(
                _close_segment(
                    open_segment,
                    budget,
                    requested_model,
                    segment_start_tokens,
                    last_tokens,
                    segment_start,
                    ts,
                )
            )
            open_segment = None
            segment_start = None
            previous_ts = ts
            previous_tokens = last_tokens
            continue
        previous_tokens = last_tokens
        previous_ts = ts

    if open_segment is not None:
        if now is None:
            now = dt.datetime.now(dt.timezone.utc)
        if segment_start is None:
            _error("segment_start missing for incomplete segment")
        open_segment = _close_segment(
            open_segment,
            budget,
            requested_model,
            segment_start_tokens if segment_start_tokens is not None else last_tokens,
            last_tokens,
            segment_start,
            now,
        )
        segments.append(open_segment)

    if not segments:
        _error("session has no task boundary records")

    aggregate = {
        "tool_calls": sum(segment["tool_calls"] for segment in segments),
        "context_compactions": sum(segment["context_compactions"] for segment in segments),
        "full_suite_runs": sum(segment["full_suite_runs"] for segment in segments),
        "runtime_seconds": sum(segment["runtime_seconds"] for segment in segments),
        "token_deltas": {
            "input": sum(segment["token_deltas"]["input"] for segment in segments),
            "cached_input": sum(segment["token_deltas"]["cached_input"] for segment in segments),
            "output": sum(segment["token_deltas"]["output"] for segment in segments),
            "reasoning": sum(segment["token_deltas"]["reasoning"] for segment in segments),
            "total": sum(segment["token_deltas"]["total"] for segment in segments),
        },
    }

    def _is_operative_segment(segment: dict[str, Any]) -> bool:
        if not segment.get("records"):
            return False
        if segment.get("tool_calls", 0):
            return True
        if segment.get("context_compactions", 0):
            return True
        if segment.get("full_suite_runs", 0):
            return True
        return False

    selected_segment = None
    for segment in reversed(segments):
        if _is_operative_segment(segment):
            selected_segment = segment
            break
    if selected_segment is None:
        selected_segment = segments[-1]

    if has_explicit_segments:
        overall_status = selected_segment["status"]
        return segments, aggregate, overall_status, selected_segment

    overall_status = selected_segment["status"]
    return segments, aggregate, overall_status, selected_segment


def main() -> int:
    args = parse_args()
    policy = _load_policy(args.budget_profile)
    requested_model = args.requested_model.strip() or DEFAULT_REQUESTED_MODEL
    sessions_root = Path(args.sessions_root).expanduser().resolve() if args.sessions_root else _sessions_root(args.codex_home)
    explicit = Path(args.session_file).expanduser().resolve() if args.session_file else None
    session_file = find_session_file(args.session_id, sessions_root, explicit)
    records = [record for _, record in _iter_json_lines(session_file)]

    now: dt.datetime | None = None
    if args.now:
        now = _parse_iso_timestamp(args.now)
        if now.tzinfo is None:
            now = now.replace(tzinfo=dt.timezone.utc)

    segments, aggregate, overall_status, selected_segment = _evaluate_records(
        records, policy["snapshot"], requested_model, now
    )
    payload = {
        "schema": SCHEMA_PATH,
        "version": SCHEMA_VERSION,
        "session_id": args.session_id,
        "session_path": str(session_file),
        "requested_model": requested_model,
        "budget_profile": policy,
        "attestation_source": selected_segment["attestation_source"],
        "attested_model": selected_segment["attested_model"],
        "status": overall_status,
        "return_status": overall_status,
        "segments": segments,
        "aggregate": aggregate,
        "soft_limit_reasons": sorted(set(selected_segment.get("soft_limit_reasons", []))),
        "hard_stop_reasons": sorted(set(selected_segment.get("hard_stop_reasons", []))),
        "session_disposition": selected_segment["session_disposition"],
        "artifact_disposition": selected_segment["artifact_disposition"],
        "artifact_validation": selected_segment["artifact_validation"],
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        if overall_status in {"needs-architect-realignment", "budget-exhausted", "model-mismatch"}:
            print(f"Session status: {overall_status} (hard stop)")
        elif overall_status == "soft-limit":
            print("Session status: soft-limit")
        else:
            print("Session status: within-budget")
        print(f"Session file: {session_file}")
        print(f"Segments: {len(segments)}")
    return _status_to_return_code(overall_status)


if __name__ == "__main__":
    raise SystemExit(main())
