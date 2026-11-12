from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
import datetime as dt
import os
from itertools import chain
from pathlib import Path
from typing import Iterator, Literal, NamedTuple

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_native_worker_session.py"
HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None


def run_cli(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def user_input_record(
    timestamp: str,
    session_id: str,
    model: str | None = None,
    *,
    attestation_source: str = "trusted-control-plane-session-metadata",
    command: str | None = None,
) -> dict:
    payload: dict[str, object] = {
        "timestamp": timestamp,
        "session_id": session_id,
        "type": "response_item",
        "turn_context": {
            "attestation_source": attestation_source,
            "token_count": {"input": 0, "cached_input": 0, "output": 0, "reasoning": 0, "total": 0},
        },
    }
    if model:
        payload["turn_context"]["model"] = model
    payload["response_item"] = {"type": "message", "role": "user"}
    if command:
        payload["response_item"]["content"] = command
    return payload


def native_record(
    timestamp: str,
    session_id: str,
    *,
    type: str = "event_msg",
    payload: object | None = None,
    turn_context: dict[str, object] | None = None,
    response_item: dict[str, object] | list[dict[str, object]] | None = None,
) -> dict:
    record: dict[str, object] = {
        "timestamp": timestamp,
        "session_id": session_id,
        "type": type,
    }
    if payload is not None:
        record["payload"] = payload
    if turn_context is not None:
        record["turn_context"] = turn_context
    if response_item is not None:
        record["response_item"] = response_item
    return record


def write_records(path: Path, records: list[dict]) -> None:
    path.write_text(
        "\n".join(json.dumps(record, separators=(",", ":")) for record in records) + "\n",
        encoding="utf-8",
    )


def spark_record(
    timestamp: str,
    session_id: str,
    event_msg: str,
    *,
    model: str = "gpt-5.3-codex-spark",
    response_type: str | None = None,
    command: str | None = None,
    turn_tokens: dict[str, int] | None = None,
    attestation_source: str = "trusted-control-plane-session-metadata",
) -> dict:
    payload: dict[str, object] = {
        "timestamp": timestamp,
        "session_id": session_id,
        "event_msg": event_msg,
        "turn_context": {
            "model": model,
            "attestation_source": attestation_source,
            "token_count": turn_tokens or {
                "input": 0,
                "cached_input": 0,
                "output": 0,
                "reasoning": 0,
                "total": 0,
            },
        },
    }
    if response_type:
        payload["response_item"] = {"type": response_type}
        if command:
            payload["response_item"]["arguments"] = json.dumps({"command": command})
    return payload


class SessionCheck(NamedTuple):
    path: tuple[str | int, ...]
    expected: object
    operation: Literal["equal", "length", "in", "not-in", "is-none"] = "equal"


class SessionCase(NamedTuple):
    original: str
    session_id: str
    records: list[dict]
    returncode: int
    checks: tuple[SessionCheck, ...]
    extra: tuple[str, ...] = ()


def _segment_budget_rows() -> Iterator[SessionCase]:

    records = [
        spark_record("2026-07-10T21:00:00Z", "drift", "task_started", model="gpt-5.3-codex-spark"),
        spark_record("2026-07-10T21:00:30Z", "drift", "task_complete", turn_tokens={"input": 2, "cached_input": 0, "output": 1, "reasoning": 0, "total": 3}),
        spark_record("2026-07-10T21:01:00Z", "drift", "task_started", model="gpt-4", turn_tokens={"input": 2, "cached_input": 0, "output": 2, "reasoning": 0, "total": 4}),
        spark_record("2026-07-10T21:01:10Z", "drift", "assistant", response_type="function_call", turn_tokens={"input": 3, "cached_input": 0, "output": 5, "reasoning": 0, "total": 8}),
        spark_record("2026-07-10T21:01:20Z", "drift", "task_complete", turn_tokens={"input": 4, "cached_input": 0, "output": 7, "reasoning": 0, "total": 11}),
    ]
    yield SessionCase('test_model_drift_between_segments', 'drift', records, 2, (
            SessionCheck(('status',), 'model-mismatch'),
            SessionCheck(('hard_stop_reasons',), 'model-mismatch', 'in'),
            SessionCheck(('session_disposition',), 'quarantined'),
            SessionCheck(('artifact_disposition',), 'rejected'),
            SessionCheck(('segments',), 2, 'length'),
            SessionCheck(('segments', 1, 'models'), ['gpt-4', 'gpt-5.3-codex-spark']),
    ))

    records = [
        {"timestamp": "2026-07-10T21:00:00Z", "session_id": "missing-model", "event_msg": "task_started", "turn_context": {"token_count": {"input": 0, "cached_input": 0, "output": 0, "reasoning": 0, "total": 0}, "attestation_source": "trusted-control-plane-session-metadata"}},
        {"timestamp": "2026-07-10T21:00:10Z", "session_id": "missing-model", "event_msg": "assistant", "response_item": {"type": "function_call"}, "turn_context": {"token_count": {"input": 2, "cached_input": 0, "output": 4, "reasoning": 0, "total": 6}}},
        {"timestamp": "2026-07-10T21:00:20Z", "session_id": "missing-model", "event_msg": "task_complete", "turn_context": {"token_count": {"input": 4, "cached_input": 0, "output": 8, "reasoning": 0, "total": 12}}},
    ]
    yield SessionCase('test_missing_model_missing_attestation', 'missing-model', records, 2, (
            SessionCheck(('session_disposition',), 'quarantined'),
            SessionCheck(('artifact_disposition',), 'rejected'),
            SessionCheck(('status',), 'model-mismatch'),
            SessionCheck(('hard_stop_reasons',), 'missing-attestation', 'in'),
    ))

    records = [
        {
            "timestamp": "2026-07-10T21:00:00Z",
            "session_id": "self-report",
            "event_msg": "task_started",
            "self_report": "I am gpt-5.3-codex-spark",
            "turn_context": {"token_count": {"input": 0, "cached_input": 0, "output": 0, "reasoning": 0, "total": 0}, "attestation_source": "trusted-control-plane-session-metadata"},
        },
        {"timestamp": "2026-07-10T21:00:10Z", "session_id": "self-report", "event_msg": "assistant", "response_item": {"type": "function_call"}, "turn_context": {"token_count": {"input": 1, "cached_input": 0, "output": 1, "reasoning": 0, "total": 2}, "attestation_source": "trusted-control-plane-session-metadata"}},
        {"timestamp": "2026-07-10T21:00:20Z", "session_id": "self-report", "event_msg": "task_complete", "turn_context": {"token_count": {"input": 2, "cached_input": 0, "output": 2, "reasoning": 0, "total": 4}, "attestation_source": "trusted-control-plane-session-metadata"}},
    ]
    yield SessionCase('test_self_report_text_ignored', 'self-report', records, 2, (
            SessionCheck(('status',), 'model-mismatch'),
    ))

    records = [
        spark_record(
            "2026-07-10T21:00:00Z",
            "hard",
            "task_started",
            turn_tokens={"input": 1, "cached_input": 0, "output": 0, "reasoning": 0, "total": 1},
        )
    ]
    start = dt.datetime.fromisoformat("2026-07-10T21:00:00+00:00")
    for i in range(104):
        records.append(
            spark_record(
                (start + dt.timedelta(seconds=i + 1)).isoformat().replace("+00:00", "Z"),
                "hard",
                "assistant",
                response_type="function_call",
                turn_tokens={"input": 1 + i + 1, "cached_input": 0, "output": i + 2, "reasoning": 0, "total": 1 + 2 * (i + 1)},
            )
        )
    records.append(
        {
            "timestamp": "2026-07-10T21:13:00Z",
            "session_id": "hard",
            "event_msg": "context_compacted",
            "turn_context": {"model": "gpt-5.3-codex-spark", "attestation_source": "trusted-control-plane-session-metadata", "token_count": {"input": 200, "cached_input": 0, "output": 150, "reasoning": 0, "total": 350}},
        }
    )
    records.append(spark_record("2026-07-10T21:02:10Z", "hard", "task_complete", turn_tokens={"input": 210, "cached_input": 0, "output": 160, "reasoning": 0, "total": 370}))
    yield SessionCase('test_tool_hard_exceeded_and_compaction', 'hard', records, 2, (
            SessionCheck(('status',), 'budget-exhausted'),
            SessionCheck(('hard_stop_reasons',), 'tool_calls_hard', 'in'),
            SessionCheck(('hard_stop_reasons',), 'max_compactions', 'in'),
            SessionCheck(('session_disposition',), 'quarantined'),
            SessionCheck(('artifact_disposition',), 'architect-adjudication-required'),
    ))

    records = [
        spark_record("2026-07-10T21:00:00Z", "soft", "task_started", turn_tokens={"input": 0, "cached_input": 0, "output": 0, "reasoning": 0, "total": 0}),
    ]
    base = dt.datetime.fromisoformat("2026-07-10T21:00:00+00:00")
    for i in range(61):
        timestamp = base + dt.timedelta(seconds=12 * i)
        records.append(
            spark_record(
                timestamp.isoformat().replace("+00:00", "Z"),
                "soft",
                "assistant",
                response_type="function_call",
                turn_tokens={"input": i, "cached_input": 0, "output": i, "reasoning": 0, "total": 2 * i},
            )
        )
    records.append(spark_record("2026-07-10T21:12:10Z", "soft", "task_complete", turn_tokens={"input": 100, "cached_input": 0, "output": 100, "reasoning": 0, "total": 200}))
    yield SessionCase('test_two_soft_limits_triggers_realignment', 'soft', records, 2, (
            SessionCheck(('status',), 'needs-architect-realignment'),
            SessionCheck(('segments', 0, 'status'), 'needs-architect-realignment'),
    ))

    records = [
        {
            "timestamp": "2026-07-10T21:00:00Z",
            "session_id": "ignore-top-level",
            "event_msg": "task_started",
            "model": "gpt-4",
            "turn_context": {"token_count": {"input": 0, "cached_input": 0, "output": 0, "reasoning": 0, "total": 0}, "attestation_source": "trusted-control-plane-session-metadata"},
        },
        {
            "timestamp": "2026-07-10T21:00:10Z",
            "session_id": "ignore-top-level",
            "event_msg": "assistant",
            "response_item": {"type": "function_call"},
            "turn_context": {"token_count": {"input": 1, "cached_input": 0, "output": 1, "reasoning": 0, "total": 2}, "attestation_source": "trusted-control-plane-session-metadata"},
        },
        {
            "timestamp": "2026-07-10T21:00:20Z",
            "session_id": "ignore-top-level",
            "event_msg": "task_complete",
            "turn_context": {"token_count": {"input": 2, "cached_input": 0, "output": 2, "reasoning": 0, "total": 4}, "attestation_source": "trusted-control-plane-session-metadata"},
        },
    ]
    yield SessionCase('test_top_level_model_field_is_ignored', 'ignore-top-level', records, 2, (
            SessionCheck(('status',), 'model-mismatch'),
            SessionCheck(('hard_stop_reasons',), 'missing-attestation', 'in'),
            SessionCheck(('hard_stop_reasons',), 'model-mismatch', 'not-in'),
    ))

    records = [
        spark_record("2026-07-10T21:00:00Z", "full-suite", "task_started"),
        spark_record(
            "2026-07-10T21:00:10Z",
            "full-suite",
            "assistant",
            response_type="function_call",
            command="python -m unittest discover -s tests -v",
        ),
        spark_record("2026-07-10T21:00:20Z", "full-suite", "task_complete", turn_tokens={"input": 2, "cached_input": 0, "output": 2, "reasoning": 0, "total": 4}),
    ]
    yield SessionCase('test_full_suite_overflow_is_hard_stop', 'full-suite', records, 2, (
            SessionCheck(('status',), 'budget-exhausted'),
            SessionCheck(('hard_stop_reasons',), 'max_full_suite_runs', 'in'),
    ))

    records = [
        spark_record("2026-07-10T21:00:00Z", "parallel-suite", "task_started"),
        spark_record(
            "2026-07-10T21:00:10Z",
            "parallel-suite",
            "assistant",
            response_type="function_call",
            command=(
                "python scripts/run_parallel_unittest.py "
                "--workers 8 --verbose"
            ),
        ),
        spark_record(
            "2026-07-10T21:00:20Z",
            "parallel-suite",
            "task_complete",
            turn_tokens={
                "input": 2,
                "cached_input": 0,
                "output": 2,
                "reasoning": 0,
                "total": 4,
            },
        ),
    ]
    yield SessionCase('test_parallel_unittest_wrapper_counts_as_one_full_suite', 'parallel-suite', records, 2, (
            SessionCheck(('segments', 0, 'full_suite_runs'), 1),
            SessionCheck(('hard_stop_reasons',), 'max_full_suite_runs', 'in'),
    ))

    records = [
        spark_record("2026-07-10T21:00:00Z", "full-suite-json", "task_started"),
        spark_record(
            "2026-07-10T21:00:10Z",
            "full-suite-json",
            "assistant",
            response_type="function_call",
            command="python -m unittest discover -s tests -v",
        ),
        spark_record("2026-07-10T21:00:20Z", "full-suite-json", "task_complete", turn_tokens={"input": 2, "cached_input": 0, "output": 2, "reasoning": 0, "total": 4}),
    ]
    records[1]["response_item"]["arguments"] = json.dumps(
        {"command": "python -m unittest discover -s tests -v"}
    )
    yield SessionCase('test_full_suite_command_with_json_argument_is_counted', 'full-suite-json', records, 2, (
            SessionCheck(('status',), 'budget-exhausted'),
            SessionCheck(('segments', 0, 'full_suite_runs'), 1),
    ))

    commands = [
        "cd /repo && python -m unittest discover -s tests -q",
        "echo ready; python3 -m unittest discover -v -s tests",
        "false || /usr/bin/python -m unittest discover -s tests",
        "echo ready\npython -m unittest discover -s tests",
        "python -m unittest discover -s tests | tee suite.log",
        (
            "python -m unittest discover -s tests; "
            "python -m unittest discover -s tests"
        ),
    ]
    records = [spark_record("2026-07-10T21:00:00Z", "shell-suite", "task_started")]
    records.extend(
        spark_record(
            f"2026-07-10T21:00:{index:02d}Z",
            "shell-suite",
            "assistant",
            response_type="function_call",
            command=command,
        )
        for index, command in enumerate(commands, start=1)
    )
    records.append(
        spark_record("2026-07-10T21:00:20Z", "shell-suite", "task_complete")
    )
    yield SessionCase('test_shell_separated_full_suite_commands_are_counted', 'shell-suite', records, 2, (
            SessionCheck(('segments', 0, 'full_suite_runs'), 7),
    ))

    commands = [
        "cd /repo && python -m unittest tests.test_focus_case",
        "echo ready; python -m unittest discover -s focused_tests",
        "printf '%s\\n' 'python -m unittest discover -s tests'",
        "echo 'python -m unittest discover -s tests' || true",
    ]
    records = [spark_record("2026-07-10T21:00:00Z", "shell-focused", "task_started")]
    records.extend(
        spark_record(
            f"2026-07-10T21:00:{index:02d}Z",
            "shell-focused",
            "assistant",
            response_type="function_call",
            command=command,
        )
        for index, command in enumerate(commands, start=1)
    )
    records.append(
        spark_record("2026-07-10T21:00:20Z", "shell-focused", "task_complete")
    )
    yield SessionCase('test_shell_separators_do_not_promote_focused_or_quoted_commands', 'shell-focused', records, 0, (
            SessionCheck(('segments', 0, 'full_suite_runs'), 0),
    ))


def _native_token_attestation_rows() -> Iterator[SessionCase]:
    records = [
        spark_record(
            "2026-07-10T21:00:00Z",
            "native-token",
            "task_started",
            model="gpt-5.3-codex-spark",
            turn_tokens={"input": 10, "cached_input": 1, "output": 3, "reasoning": 2, "total": 16},
        ),
        {
            "timestamp": "2026-07-10T21:00:10Z",
            "session_id": "native-token",
            "type": "event_msg",
            "event_msg": "assistant",
            "payload": {
                "type": "token_count",
                "info": {
                    "total_token_usage": {
                        "input_tokens": 40,
                        "cached_input_tokens": 4,
                        "output_tokens": 16,
                        "reasoning_output_tokens": 5,
                        "total_tokens": 65,
                    }
                }
            },
            "turn_context": {"model": "gpt-5.3-codex-spark"},
        },
        {
            "timestamp": "2026-07-10T21:00:20Z",
            "session_id": "native-token",
            "type": "event_msg",
            "event_msg": "task_complete",
            "turn_context": {
                "model": "gpt-5.3-codex-spark",
                "token_count": {"input": 5, "cached_input": 1, "output": 3, "reasoning": 0, "total": 9},
            },
        },
    ]
    yield SessionCase('test_token_count_from_native_event_payload_and_non_negative', 'native-token', records, 0, (
            SessionCheck(('segments', 0, 'token_deltas', 'input'), 0),
            SessionCheck(('segments', 0, 'token_deltas', 'cached_input'), 0),
            SessionCheck(('segments', 0, 'token_deltas', 'output'), 0),
            SessionCheck(('segments', 0, 'token_deltas', 'reasoning'), 0),
            SessionCheck(('segments', 0, 'token_deltas', 'total'), 0),
    ))


    records = [
        {
            "timestamp": "2026-07-10T21:00:00Z",
            "session_id": "raw-top-level",
            "type": "event_msg",
            "event_msg": "task_started",
            "payload": {
                "event_msg": "task_started",
            },
            "turn_context": {"model": "gpt-5.3-codex-spark"},
        },
        {
            "timestamp": "2026-07-10T21:00:10Z",
            "session_id": "raw-top-level",
            "type": "event_msg",
            "event_msg": "task_complete",
            "turn_context": {"model": "gpt-5.3-codex-spark"},
        },
    ]
    yield SessionCase('test_raw_native_top_level_selected_attestation_propagates', 'raw-top-level', records, 0, (
            SessionCheck(('attestation_source',), 'turn_context'),
            SessionCheck(('attested_model',), 'gpt-5.3-codex-spark'),
            SessionCheck(('segments', 0, 'attestation_source'), 'turn_context'),
            SessionCheck(('segments', 0, 'attested_model'), 'gpt-5.3-codex-spark'),
    ))

    records = [
        spark_record(
            "2026-07-10T21:00:00Z",
            "trailing-attestation",
            "task_started",
            response_type="function_call",
            command="echo first",
        ),
        spark_record(
            "2026-07-10T21:00:10Z",
            "trailing-attestation",
            "task_complete",
        ),
        {
            "timestamp": "2026-07-10T21:00:20Z",
            "session_id": "trailing-attestation",
            "type": "event_msg",
            "event_msg": "task_started",
            "turn_context": {
                "attestation_source": "trusted-control-plane-session-metadata",
                "token_count": {
                    "input": 2,
                    "cached_input": 0,
                    "output": 2,
                    "reasoning": 0,
                    "total": 4,
                },
            },
        },
        {
            "timestamp": "2026-07-10T21:00:30Z",
            "session_id": "trailing-attestation",
            "type": "event_msg",
            "event_msg": "task_complete",
            "turn_context": {"attestation_source": "trusted-control-plane-session-metadata", "token_count": {"input": 4, "cached_input": 0, "output": 4, "reasoning": 0, "total": 8}},
        },
    ]
    yield SessionCase('test_trailing_attestation_only_segment_is_not_operative', 'trailing-attestation', records, 2, (
            SessionCheck(('status',), 'model-mismatch'),
            SessionCheck(('return_status',), 'model-mismatch'),
            SessionCheck(('attestation_source',), 'trusted-control-plane-session-metadata'),
            SessionCheck(('attested_model',), None, 'is-none'),
            SessionCheck(('hard_stop_reasons',), ['missing-attestation']),
    ))

    records = [
        spark_record(
            "2026-07-10T21:00:00Z",
            "native-token-aliases",
            "task_started",
            model="gpt-5.3-codex-spark",
            turn_tokens={"input": 0, "cached_input": 0, "output": 0, "reasoning": 0, "total": 0},
        ),
        {
            "timestamp": "2026-07-10T21:00:10Z",
            "session_id": "native-token-aliases",
            "type": "event_msg",
            "event_msg": "assistant",
            "payload": {
                "type": "token_count",
                "info": {
                    "total_token_usage": {
                        "input_tokens": 10,
                        "cached_input_tokens": 1,
                        "output_tokens": 9,
                        "reasoning_output_tokens": 5,
                        "total_tokens": 25,
                    }
                }
            },
            "turn_context": {"model": "gpt-5.3-codex-spark"},
        },
        spark_record(
            "2026-07-10T21:00:20Z",
            "native-token-aliases",
            "task_complete",
            turn_tokens={"input": 10, "cached_input": 1, "output": 9, "reasoning": 5, "total": 25},
        ),
    ]
    yield SessionCase('test_token_count_uses_native_event_shape_aliases', 'native-token-aliases', records, 0, (
            SessionCheck(('segments', 0, 'token_deltas', 'input'), 10),
            SessionCheck(('segments', 0, 'token_deltas', 'cached_input'), 1),
            SessionCheck(('segments', 0, 'token_deltas', 'output'), 9),
            SessionCheck(('segments', 0, 'token_deltas', 'reasoning'), 5),
            SessionCheck(('segments', 0, 'token_deltas', 'total'), 25),
    ))


    records = [
        spark_record("2026-07-10T21:00:00Z", "incomplete", "task_started"),
        spark_record("2026-07-10T21:00:10Z", "incomplete", "assistant", response_type="function_call"),
    ]
    yield SessionCase('test_incomplete_segment_uses_now', 'incomplete', records, 0, (
            SessionCheck(('segments', 0, 'status'), 'soft-limit'),
            SessionCheck(('segments', 0, 'runtime_seconds'), 780.0),
            SessionCheck(('status',), 'soft-limit'),
    ), extra=('--now', '2026-07-10T21:13:00Z'))


def _fallback_segment_rows() -> Iterator[SessionCase]:


    records = [
        {
            "timestamp": "2026-07-10T21:00:00Z",
            "session_id": "native-top-level-payload",
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "user",
            },
            "turn_context": {
                "model": "gpt-5.3-codex-spark",
                "attestation_source": "trusted-control-plane-session-metadata",
                "token_count": {"input": 1, "cached_input": 0, "output": 1, "reasoning": 0, "total": 2},
            },
        },
        spark_record(
            "2026-07-10T21:00:10Z",
            "native-top-level-payload",
            "assistant",
            response_type="function_call",
            command="echo smoke",
            turn_tokens={"input": 2, "cached_input": 0, "output": 2, "reasoning": 0, "total": 4},
        ),
        spark_record(
            "2026-07-10T21:00:20Z",
            "native-top-level-payload",
            "task_complete",
            turn_tokens={"input": 3, "cached_input": 0, "output": 3, "reasoning": 0, "total": 6},
        ),
    ]
    yield SessionCase('test_cli_uses_top_level_native_payload_for_user_boundary', 'native-top-level-payload', records, 0, (
            SessionCheck(('segments',), 1, 'length'),
            SessionCheck(('segments', 0, 'tool_calls'), 1),
            SessionCheck(('segments', 0, 'status'), 'within-budget'),
    ))

    records = [
        user_input_record(
            "2026-07-10T21:00:00Z",
            "fallback-compaction",
        ),
        user_input_record(
            "2026-07-10T21:00:10Z",
            "fallback-compaction",
            "gpt-5.3-codex-spark",
        ),
        spark_record(
            "2026-07-10T21:00:20Z",
            "fallback-compaction",
            "assistant",
            response_type="function_call",
            turn_tokens={"input": 1, "cached_input": 0, "output": 1, "reasoning": 0, "total": 2},
        ),
        {
            "timestamp": "2026-07-10T21:00:30Z",
            "session_id": "fallback-compaction",
            "event_msg": "context_compacted",
            "turn_context": {
                "model": "gpt-5.3-codex-spark",
                "attestation_source": "trusted-control-plane-session-metadata",
                "token_count": {"input": 2, "cached_input": 0, "output": 2, "reasoning": 0, "total": 4},
            },
        },
        spark_record(
            "2026-07-10T21:00:40Z",
            "fallback-compaction",
            "task_complete",
            turn_tokens={"input": 4, "cached_input": 0, "output": 3, "reasoning": 0, "total": 7},
        ),
        user_input_record(
            "2026-07-10T21:00:50Z",
            "fallback-compaction",
            "gpt-5.3-codex-spark",
        ),
    ]
    yield SessionCase('test_fallback_segmentation_attestation_then_work_with_compaction', 'fallback-compaction', records, 2, (
            SessionCheck(('segments',), 3, 'length'),
            SessionCheck(('segments', 0, 'tool_calls'), 0),
            SessionCheck(('segments', 1, 'tool_calls'), 1),
            SessionCheck(('segments', 1, 'context_compactions'), 1),
            SessionCheck(('segments', 2, 'tool_calls'), 0),
            SessionCheck(('segments', 2, 'context_compactions'), 0),
            SessionCheck(('segments', 2, 'full_suite_runs'), 0),
            SessionCheck(('status',), 'budget-exhausted'),
            SessionCheck(('return_status',), 'budget-exhausted'),
            SessionCheck(('hard_stop_reasons',), 'max_compactions', 'in'),
            SessionCheck(('attestation_source',), 'turn_context'),
            SessionCheck(('attested_model',), 'gpt-5.3-codex-spark'),
            SessionCheck(('segments', 1, 'attestation_source'), 'turn_context'),
            SessionCheck(('segments', 1, 'attested_model'), 'gpt-5.3-codex-spark'),
            SessionCheck(('segments', 1, 'status'), 'budget-exhausted'),
            SessionCheck(('segments', 1, 'full_suite_runs'), 0),
            SessionCheck(('segments', 1, 'return_status'), 'budget-exhausted'),
    ), extra=('--now', '2026-07-10T21:01:00Z'))

    records = [
        user_input_record(
            "2026-07-10T21:00:00Z",
            "fallback-tool-isolation",
            "gpt-5.3-codex-spark",
        ),
        spark_record(
            "2026-07-10T21:00:10Z",
            "fallback-tool-isolation",
            "assistant",
            response_type="function_call",
            turn_tokens={"input": 1, "cached_input": 0, "output": 1, "reasoning": 0, "total": 2},
        ),
        user_input_record(
            "2026-07-10T21:00:20Z",
            "fallback-tool-isolation",
            "gpt-5.3-codex-spark",
        ),
        spark_record(
            "2026-07-10T21:00:30Z",
            "fallback-tool-isolation",
            "assistant",
            response_type="function_call",
            turn_tokens={"input": 1, "cached_input": 0, "output": 1, "reasoning": 0, "total": 2},
        ),
        spark_record(
            "2026-07-10T21:00:40Z",
            "fallback-tool-isolation",
            "assistant",
            response_type="function_call",
            turn_tokens={"input": 1, "cached_input": 0, "output": 1, "reasoning": 0, "total": 2},
        ),
    ]
    yield SessionCase('test_fallback_segmentation_tool_isolation', 'fallback-tool-isolation', records, 0, (
            SessionCheck(('segments',), 2, 'length'),
            SessionCheck(('segments', 0, 'tool_calls'), 1),
            SessionCheck(('segments', 1, 'tool_calls'), 2),
            SessionCheck(('aggregate', 'tool_calls'), 3),
    ), extra=('--now', '2026-07-10T21:00:50Z'))


class SessionTopologyCase(NamedTuple):
    original: str
    session_id: str
    source: Literal["environment", "home-flag", "root"]
    home_directory: str | None
    files: tuple[tuple[str, list[dict] | str], ...]
    expected_path: str | None
    diagnostic: str | None = None


def _session_source_topologies() -> Iterator[SessionTopologyCase]:
    for original, session_id, source, directory in (
        ("test_default_sessions_root_falls_back_to_codex_home", "default-root", "environment", "codex-home"),
        ("test_codex_home_flag_targets_sessions_subdir", "custom-home", "home-flag", "custom-home"),
    ):
        records = [
            spark_record("2026-07-10T21:00:00Z", session_id, "task_started",
                         turn_tokens={"input": 0, "cached_input": 0, "output": 0, "reasoning": 0, "total": 0}),
            spark_record("2026-07-10T21:00:10Z", session_id, "task_complete",
                         turn_tokens={"input": 1, "cached_input": 0, "output": 2, "reasoning": 0, "total": 3}),
        ]
        yield SessionTopologyCase(original, session_id, source, directory, (("session.jsonl", records),), "session.jsonl")
    session_id = "session-match"
    yield SessionTopologyCase("test_filename_match_ignores_unrelated_malformed_jsonl", session_id, "root", None, (
        ("legacy_bad_record.jsonl", '{"session_id":"legacy","event"'),
        ("session-match-2026-07-10.jsonl", [
            spark_record("2026-07-10T21:00:00Z", session_id, "task_started"),
            spark_record("2026-07-10T21:00:10Z", session_id, "assistant", response_type="function_call"),
            spark_record("2026-07-10T21:00:20Z", session_id, "task_complete"),
        ]),
    ), "session-match-2026-07-10.jsonl")
    session_id = "dup-session-id"
    yield SessionTopologyCase("test_duplicate_filename_session_matches_fail", session_id, "root", None, (
        (f"{session_id}-a.jsonl", [spark_record("2026-07-10T21:00:00Z", session_id, "task_started")]),
        (f"archive-{session_id}-b.jsonl", [spark_record("2026-07-10T21:00:10Z", session_id, "task_started")]),
    ), None, "ambiguous")
    session_id = "malformed-session"
    yield SessionTopologyCase("test_filename_matched_malformed_session_file_fails", session_id, "root", None, (
        (f"{session_id}-session.jsonl", '{"session_id":"malformed-session","event"'),
    ), None, "invalid json")


class CheckNativeWorkerSessionTests(unittest.TestCase):
    def test_explicit_native_session_file_matches_session_meta_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
            session_id = "native-child-session"
            task_records = [
                spark_record("2026-07-10T21:00:00Z", session_id, "task_started"),
                spark_record("2026-07-10T21:00:10Z", session_id, "assistant", response_type="function_call"),
                spark_record("2026-07-10T21:00:20Z", session_id, "task_complete"),
            ]
            for record in task_records:
                record.pop("session_id", None)
            write_records(
                session_file,
                [
                    {
                        "timestamp": "2026-07-10T20:59:59Z",
                        "type": "session_meta",
                        "payload": {"id": session_id, "session_id": "parent-session"},
                    },
                    *task_records,
                ],
            )

            result = run_cli(
                "--session-id",
                session_id,
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--session-file",
                str(session_file),
                "--json",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["session_id"], session_id)
            self.assertEqual(payload["aggregate"]["tool_calls"], 1)

    def test_session_cli_segment_budget_rows(self) -> None:
        rows = chain(_segment_budget_rows(), _native_token_attestation_rows(), _fallback_segment_rows())
        for row in rows:
            with self.subTest(original=row.original), tempfile.TemporaryDirectory() as tmpdir:
                session_file = Path(tmpdir) / "session.jsonl"
                write_records(session_file, row.records)
                result = run_cli(
                    "--session-id", row.session_id, "--requested-model", "gpt-5.3-codex-spark",
                    "--budget-profile", "implementation", "--session-file", str(session_file), "--json", *row.extra,
                )
                self.assertEqual(result.returncode, row.returncode, result.stderr)
                payload = json.loads(result.stdout)
                for check in row.checks:
                    with self.subTest(path=check.path, operation=check.operation):
                        self._assert_session_check(payload, check)

    def _assert_session_check(self, payload: dict, check: SessionCheck) -> None:
        value = payload
        for key in check.path:
            value = value[key]
        if check.operation == "length":
            self.assertEqual(len(value), check.expected)
        elif check.operation == "in":
            self.assertIn(check.expected, value)
        elif check.operation == "not-in":
            self.assertNotIn(check.expected, value)
        elif check.operation == "is-none":
            self.assertIsNone(value)
        else:
            self.assertEqual(value, check.expected)


    def test_session_cli_source_topology_rows(self) -> None:
        for row in _session_source_topologies():
            with self.subTest(original=row.original), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                env = None
                if row.home_directory:
                    codex_home = root / row.home_directory
                    root = codex_home / "sessions"
                    root.mkdir(parents=True)
                for filename, content in row.files:
                    path = root / filename
                    if isinstance(content, str):
                        path.write_text(content, encoding="utf-8")
                    else:
                        write_records(path, content)
                if row.source == "environment":
                    env = os.environ.copy()
                    env["CODEX_HOME"] = str(codex_home)
                    source_args = ()
                elif row.source == "home-flag":
                    source_args = ("--codex-home", str(codex_home))
                else:
                    source_args = ("--sessions-root", str(root))
                result = run_cli(
                    "--session-id", row.session_id, "--requested-model", "gpt-5.3-codex-spark",
                    "--budget-profile", "implementation", *source_args, "--json", env=env,
                )
                if row.diagnostic:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(row.diagnostic, result.stderr.lower())
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(json.loads(result.stdout)["session_path"], str(root / row.expected_path))


    def test_mutually_exclusive_session_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "root"
            root.mkdir()
            file = root / "session.jsonl"
            write_records(file, [spark_record("2026-07-10T21:00:00Z", "conflict", "task_started"), spark_record("2026-07-10T21:00:10Z", "conflict", "task_complete")])
            result = run_cli(
                "--session-id",
                "conflict",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--sessions-root",
                str(root),
                "--session-file",
                str(file),
                "--json",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not allowed with", result.stderr.lower())


    def test_focused_suite_commands_do_not_count_as_full_suite(self) -> None:
        variants = (
            ('test_focused_unittest_does_not_count_as_full_suite',
             'focused-suite',
             'python -m unittest tests.test_focus_case',
             4,
             6),
            ('test_focused_parallel_unittest_wrapper_is_not_a_full_suite',
             'parallel-focused',
             'python scripts/run_parallel_unittest.py --workers 8 --start-directory focused_tests',
             2,
             4),
        )
        for original, session_id, command, output_tokens, total_tokens in variants:
            with self.subTest(original=original):
                with tempfile.TemporaryDirectory() as tmpdir:
                    session_file = Path(tmpdir) / "session.jsonl"
                    records = [
                        spark_record("2026-07-10T21:00:00Z", session_id, "task_started"),
                        spark_record(
                            "2026-07-10T21:00:10Z",
                            session_id,
                            "assistant",
                            response_type="function_call",
                            command=command,
                        ),
                        spark_record(
                            "2026-07-10T21:00:20Z",
                            session_id,
                            "task_complete",
                            turn_tokens={"input": 2, "cached_input": 0, "output": output_tokens, "reasoning": 0, "total": total_tokens},
                        ),
                    ]
                    write_records(session_file, records)
                    result = run_cli(
                        "--session-id",
                        session_id,
                        "--requested-model",
                        "gpt-5.3-codex-spark",
                        "--budget-profile",
                        "implementation",
                        "--session-file",
                        str(session_file),
                        "--json",
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    payload = json.loads(result.stdout)
                    self.assertEqual(payload["segments"][0]["full_suite_runs"], 0)
                    self.assertEqual(payload["status"], "within-budget")


    def test_malformed_and_ambiguous_session_file_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            malformed = Path(tmpdir) / "bad_record.jsonl"
            malformed.write_text('{"session_id":"bad","event"', encoding="utf-8")
            result_malformed = run_cli(
                "--session-id",
                "bad",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--session-file",
                str(malformed),
                "--json",
            )
            self.assertNotEqual(result_malformed.returncode, 0)
            self.assertIn("invalid json", result_malformed.stderr.lower())

            ambiguous_root = Path(tmpdir) / "ambiguity"
            ambiguous_root.mkdir()
            shared_one = ambiguous_root / "one.jsonl"
            shared_two = ambiguous_root / "two.jsonl"
            write_records(
                shared_one,
                [
                    spark_record("2026-07-10T21:00:00Z", "shared", "task_started"),
                    spark_record("2026-07-10T21:00:10Z", "shared", "task_complete"),
                ],
            )
            write_records(
                shared_two,
                [
                    spark_record("2026-07-10T21:01:00Z", "shared", "task_started"),
                    spark_record("2026-07-10T21:01:10Z", "shared", "task_complete"),
                ],
            )
            result_ambiguous = run_cli(
                "--session-id",
                "shared",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--sessions-root",
                str(ambiguous_root),
                "--json",
            )
            self.assertNotEqual(result_ambiguous.returncode, 0)
            self.assertIn("ambiguous", result_ambiguous.stderr.lower())


    def test_output_schema_instances_when_jsonschema_available(self) -> None:
        if not HAS_JSONSCHEMA:
            self.skipTest("jsonschema is not installed in test environment")
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
            records = [
                spark_record("2026-07-10T21:00:00Z", "schema", "task_started"),
                spark_record("2026-07-10T21:00:10Z", "schema", "assistant", response_type="function_call"),
                spark_record("2026-07-10T21:00:20Z", "schema", "task_complete"),
            ]
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "schema",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--session-file",
                str(session_file),
                "--json",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            schema = json.loads((ROOT / "schemas" / "native-worker-session-check.schema.json").read_text(encoding="utf-8"))
            from jsonschema import Draft202012Validator

            Draft202012Validator(schema).validate(payload)


    def test_non_full_suite_tool_calls_do_not_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
            records = [
                spark_record("2026-07-10T21:00:00Z", "non-full-suite", "task_started"),
                spark_record(
                    "2026-07-10T21:00:10Z",
                    "non-full-suite",
                    "assistant",
                    response_type="function_call",
                    command="python -m py_compile checks.py",
                ),
                {
                    "timestamp": "2026-07-10T21:00:20Z",
                    "session_id": "non-full-suite",
                    "type": "event_msg",
                    "event_msg": "assistant",
                    "response_item": {
                        "type": "function_call",
                        "arguments": json.dumps({"command": "python -m compileall"}),
                    },
                },
                spark_record("2026-07-10T21:00:30Z", "non-full-suite", "task_complete"),
            ]
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "non-full-suite",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--session-file",
                str(session_file),
                "--json",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["segments"][0]["full_suite_runs"], 0)
            self.assertEqual(payload["status"], "within-budget")


    def test_valid_two_segment_spark(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            session_file = root / "session.jsonl"
            records = [
                spark_record("2026-07-10T21:00:00Z", "session-two", "task_started", turn_tokens={"input": 1, "cached_input": 0, "output": 1, "reasoning": 0, "total": 2}),
                spark_record("2026-07-10T21:00:10Z", "session-two", "assistant", response_type="function_call", turn_tokens={"input": 2, "cached_input": 0, "output": 4, "reasoning": 0, "total": 6}),
                spark_record("2026-07-10T21:00:20Z", "session-two", "task_complete", turn_tokens={"input": 3, "cached_input": 0, "output": 6, "reasoning": 0, "total": 9}),
                spark_record("2026-07-10T21:05:00Z", "session-two", "task_started", turn_tokens={"input": 4, "cached_input": 0, "output": 6, "reasoning": 0, "total": 10}),
                spark_record("2026-07-10T21:05:10Z", "session-two", "assistant", response_type="function_call", turn_tokens={"input": 5, "cached_input": 0, "output": 8, "reasoning": 0, "total": 13}),
                spark_record("2026-07-10T21:05:20Z", "session-two", "task_complete", turn_tokens={"input": 8, "cached_input": 1, "output": 10, "reasoning": 1, "total": 20}),
            ]
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "session-two",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--session-file",
                str(session_file),
                "--json",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "within-budget")
            self.assertEqual(len(payload["segments"]), 2)
            self.assertEqual(payload["segments"][0]["models"], ["gpt-5.3-codex-spark"])
            self.assertEqual(payload["segments"][1]["models"], ["gpt-5.3-codex-spark"])
            self.assertEqual(payload["segments"][0]["token_deltas"]["total"], 7)
            self.assertEqual(payload["segments"][1]["token_deltas"]["total"], 10)
            self.assertEqual(payload["session_disposition"], "accepted")
            self.assertEqual(payload["artifact_disposition"], "accepted")
            self.assertEqual(payload["segments"][1]["artifact_disposition"], "accepted")

    def test_native_token_count_with_cumulative_reset(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
            records = [
                spark_record(
                    "2026-07-10T21:00:00Z",
                    "native-token-reset",
                    "task_started",
                    model="gpt-5.3-codex-spark",
                    turn_tokens={"input": 100, "cached_input": 0, "output": 0, "reasoning": 0, "total": 100},
                ),
                {
                    "timestamp": "2026-07-10T21:00:10Z",
                    "session_id": "native-token-reset",
                    "type": "event_msg",
                    "event_msg": "assistant",
                    "turn_context": {"model": "gpt-5.3-codex-spark"},
                    "payload": {
                        "type": "token_count",
                        "info": {
                            "total_token_usage": {
                                "input_tokens": 40,
                                "cached_input_tokens": 0,
                                "output_tokens": 12,
                                "reasoning_output_tokens": 2,
                                "total_tokens": 25,
                            }
                        }
                    },
                },
                {
                    "timestamp": "2026-07-10T21:00:20Z",
                    "session_id": "native-token-reset",
                    "type": "event_msg",
                    "event_msg": "task_complete",
                    "turn_context": {"model": "gpt-5.3-codex-spark"},
                },
            ]
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "native-token-reset",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--session-file",
                str(session_file),
                "--json",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["segments"][0]["token_deltas"]["total"], 0)
            self.assertEqual(payload["segments"][0]["token_deltas"]["input"], 0)

    def test_turn_context_model_acceptance_sets_turn_context_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
            records = [
                spark_record(
                    "2026-07-10T21:00:00Z",
                    "attest-turn-context",
                    "task_started",
                    model="gpt-5.3-codex-spark",
                    turn_tokens={"input": 1, "cached_input": 0, "output": 1, "reasoning": 0, "total": 2},
                ),
                spark_record(
                    "2026-07-10T21:00:10Z",
                    "attest-turn-context",
                    "assistant",
                    response_type="function_call",
                    turn_tokens={"input": 2, "cached_input": 0, "output": 2, "reasoning": 0, "total": 4},
                    attestation_source="trusted-control-plane-session-metadata",
                ),
                spark_record(
                    "2026-07-10T21:00:20Z",
                    "attest-turn-context",
                    "task_complete",
                    turn_tokens={"input": 3, "cached_input": 0, "output": 3, "reasoning": 0, "total": 6},
                ),
            ]
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "attest-turn-context",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--session-file",
                str(session_file),
                "--json",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["attestation_source"], "turn_context")
            self.assertEqual(payload["attested_model"], "gpt-5.3-codex-spark")
            self.assertEqual(payload["segments"][0]["attestation_source"], "turn_context")
            self.assertEqual(payload["segments"][0]["attested_model"], "gpt-5.3-codex-spark")

    def test_fallback_segmentation_attestation_then_work_segment(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
            records = [
                user_input_record(
                    "2026-07-10T21:00:00Z",
                    "fallback-attestation",
                ),
                user_input_record(
                    "2026-07-10T21:00:10Z",
                    "fallback-attestation",
                    "gpt-5.3-codex-spark",
                ),
                spark_record(
                    "2026-07-10T21:00:20Z",
                    "fallback-attestation",
                    "assistant",
                    response_type="function_call",
                    turn_tokens={"input": 1, "cached_input": 0, "output": 1, "reasoning": 0, "total": 2},
                ),
            ]
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "fallback-attestation",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--session-file",
                str(session_file),
                "--json",
                "--now",
                "2026-07-10T21:00:30Z",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(len(payload["segments"]), 2)
            self.assertEqual(payload["segments"][0]["tool_calls"], 0)
            self.assertEqual(payload["segments"][1]["tool_calls"], 1)
            self.assertEqual(payload["segments"][1]["status"], "within-budget")
            self.assertEqual(payload["status"], "within-budget")

    def test_fallback_segmentation_with_normalized_user_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
            records = [
                {
                    "timestamp": "2026-07-10T21:00:00Z",
                    "session_id": "normalized-user-boundary",
                    "type": "response_item",
                    "response_item": {
                        "type": "message",
                        "role": "user",
                    },
                    "turn_context": {
                        "model": "gpt-5.3-codex-spark",
                        "attestation_source": "trusted-control-plane-session-metadata",
                        "token_count": {"input": 1, "cached_input": 0, "output": 1, "reasoning": 0, "total": 2},
                    },
                },
                spark_record(
                    "2026-07-10T21:00:10Z",
                    "normalized-user-boundary",
                    "assistant",
                    response_type="function_call",
                    turn_tokens={"input": 2, "cached_input": 0, "output": 2, "reasoning": 0, "total": 4},
                ),
                spark_record(
                    "2026-07-10T21:00:20Z",
                    "normalized-user-boundary",
                    "task_complete",
                    turn_tokens={"input": 3, "cached_input": 0, "output": 3, "reasoning": 0, "total": 6},
                ),
            ]
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "normalized-user-boundary",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--session-file",
                str(session_file),
                "--json",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(len(payload["segments"]), 1)
            self.assertEqual(payload["segments"][0]["tool_calls"], 1)
            self.assertEqual(payload["segments"][0]["status"], "within-budget")


if __name__ == "__main__":
    unittest.main()
