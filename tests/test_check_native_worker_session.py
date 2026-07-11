from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
import datetime as dt
import os
from pathlib import Path

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


class CheckNativeWorkerSessionTests(unittest.TestCase):
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

    def test_model_drift_between_segments(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
            records = [
                spark_record("2026-07-10T21:00:00Z", "drift", "task_started", model="gpt-5.3-codex-spark"),
                spark_record("2026-07-10T21:00:30Z", "drift", "task_complete", turn_tokens={"input": 2, "cached_input": 0, "output": 1, "reasoning": 0, "total": 3}),
                spark_record("2026-07-10T21:01:00Z", "drift", "task_started", model="gpt-4", turn_tokens={"input": 2, "cached_input": 0, "output": 2, "reasoning": 0, "total": 4}),
                spark_record("2026-07-10T21:01:10Z", "drift", "assistant", response_type="function_call", turn_tokens={"input": 3, "cached_input": 0, "output": 5, "reasoning": 0, "total": 8}),
                spark_record("2026-07-10T21:01:20Z", "drift", "task_complete", turn_tokens={"input": 4, "cached_input": 0, "output": 7, "reasoning": 0, "total": 11}),
            ]
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "drift",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--session-file",
                str(session_file),
                "--json",
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "model-mismatch")
            self.assertIn("model-mismatch", payload["hard_stop_reasons"])
            self.assertEqual(len(payload["segments"]), 2)
            self.assertEqual(payload["segments"][1]["models"], ["gpt-4", "gpt-5.3-codex-spark"])

    def test_missing_model_missing_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
            records = [
                {"timestamp": "2026-07-10T21:00:00Z", "session_id": "missing-model", "event_msg": "task_started", "turn_context": {"token_count": {"input": 0, "cached_input": 0, "output": 0, "reasoning": 0, "total": 0}, "attestation_source": "trusted-control-plane-session-metadata"}},
                {"timestamp": "2026-07-10T21:00:10Z", "session_id": "missing-model", "event_msg": "assistant", "response_item": {"type": "function_call"}, "turn_context": {"token_count": {"input": 2, "cached_input": 0, "output": 4, "reasoning": 0, "total": 6}}},
                {"timestamp": "2026-07-10T21:00:20Z", "session_id": "missing-model", "event_msg": "task_complete", "turn_context": {"token_count": {"input": 4, "cached_input": 0, "output": 8, "reasoning": 0, "total": 12}}},
            ]
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "missing-model",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--session-file",
                str(session_file),
                "--json",
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "model-mismatch")
            self.assertIn("missing-attestation", payload["hard_stop_reasons"])

    def test_self_report_text_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
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
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "self-report",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--session-file",
                str(session_file),
                "--json",
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "model-mismatch")

    def test_tool_hard_exceeded_and_compaction(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
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
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "hard",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--session-file",
                str(session_file),
                "--json",
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "budget-exhausted")
            self.assertIn("tool_calls_hard", payload["hard_stop_reasons"])
            self.assertIn("max_compactions", payload["hard_stop_reasons"])

    def test_two_soft_limits_triggers_realignment(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
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
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "soft",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--session-file",
                str(session_file),
                "--json",
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "needs-architect-realignment")
            self.assertEqual(payload["segments"][0]["status"], "needs-architect-realignment")

    def test_default_sessions_root_falls_back_to_codex_home(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            codex_home = Path(tmpdir) / "codex-home"
            session_root = codex_home / "sessions"
            session_root.mkdir(parents=True)
            session_file = session_root / "session.jsonl"
            records = [
                spark_record(
                    "2026-07-10T21:00:00Z",
                    "default-root",
                    "task_started",
                    turn_tokens={"input": 0, "cached_input": 0, "output": 0, "reasoning": 0, "total": 0},
                ),
                spark_record(
                    "2026-07-10T21:00:10Z",
                    "default-root",
                    "task_complete",
                    turn_tokens={"input": 1, "cached_input": 0, "output": 2, "reasoning": 0, "total": 3},
                ),
            ]
            write_records(session_file, records)
            env = os.environ.copy()
            env["CODEX_HOME"] = str(codex_home)
            result = run_cli(
                "--session-id",
                "default-root",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--json",
                env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["session_path"], str(session_file))

    def test_codex_home_flag_targets_sessions_subdir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            codex_home = Path(tmpdir) / "custom-home"
            session_root = codex_home / "sessions"
            session_root.mkdir(parents=True)
            session_file = session_root / "session.jsonl"
            records = [
                spark_record(
                    "2026-07-10T21:00:00Z",
                    "custom-home",
                    "task_started",
                    turn_tokens={"input": 0, "cached_input": 0, "output": 0, "reasoning": 0, "total": 0},
                ),
                spark_record(
                    "2026-07-10T21:00:10Z",
                    "custom-home",
                    "task_complete",
                    turn_tokens={"input": 1, "cached_input": 0, "output": 2, "reasoning": 0, "total": 3},
                ),
            ]
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "custom-home",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--codex-home",
                str(codex_home),
                "--json",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["session_path"], str(session_file))

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

    def test_top_level_model_field_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
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
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "ignore-top-level",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--session-file",
                str(session_file),
                "--json",
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "model-mismatch")
            self.assertIn("missing-attestation", payload["hard_stop_reasons"])
            self.assertNotIn("model-mismatch", payload["hard_stop_reasons"])

    def test_full_suite_overflow_is_hard_stop(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
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
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "full-suite",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--session-file",
                str(session_file),
                "--json",
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "budget-exhausted")
            self.assertIn("max_full_suite_runs", payload["hard_stop_reasons"])

    def test_focused_unittest_does_not_count_as_full_suite(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
            records = [
                spark_record("2026-07-10T21:00:00Z", "focused-suite", "task_started"),
                spark_record(
                    "2026-07-10T21:00:10Z",
                    "focused-suite",
                    "assistant",
                    response_type="function_call",
                    command="python -m unittest tests.test_focus_case",
                ),
                spark_record(
                    "2026-07-10T21:00:20Z",
                    "focused-suite",
                    "task_complete",
                    turn_tokens={"input": 2, "cached_input": 0, "output": 4, "reasoning": 0, "total": 6},
                ),
            ]
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "focused-suite",
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

    def test_full_suite_command_with_json_argument_is_counted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
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
            # mimic tool payloads where command is wrapped in JSON arguments
            records[1]["response_item"]["arguments"] = json.dumps(
                {"command": "python -m unittest discover -s tests -v"}
            )
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "full-suite-json",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--session-file",
                str(session_file),
                "--json",
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "budget-exhausted")
            self.assertEqual(payload["segments"][0]["full_suite_runs"], 1)

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

    def test_token_count_from_native_event_payload_and_non_negative(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
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
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "native-token",
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
            self.assertEqual(payload["segments"][0]["token_deltas"]["input"], 0)
            self.assertEqual(payload["segments"][0]["token_deltas"]["cached_input"], 0)
            self.assertEqual(payload["segments"][0]["token_deltas"]["output"], 0)
            self.assertEqual(payload["segments"][0]["token_deltas"]["reasoning"], 0)
            self.assertEqual(payload["segments"][0]["token_deltas"]["total"], 0)

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

    def test_raw_native_top_level_selected_attestation_propagates(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
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
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "raw-top-level",
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

    def test_trailing_attestation_only_segment_is_not_operative(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
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
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "trailing-attestation",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--session-file",
                str(session_file),
                "--json",
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "model-mismatch")
            self.assertEqual(payload["return_status"], "model-mismatch")
            self.assertEqual(payload["attestation_source"], "trusted-control-plane-session-metadata")
            self.assertIsNone(payload["attested_model"])
            self.assertEqual(payload["hard_stop_reasons"], ["missing-attestation"])

    def test_token_count_uses_native_event_shape_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
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
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "native-token-aliases",
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
            self.assertEqual(payload["segments"][0]["token_deltas"]["input"], 10)
            self.assertEqual(payload["segments"][0]["token_deltas"]["cached_input"], 1)
            self.assertEqual(payload["segments"][0]["token_deltas"]["output"], 9)
            self.assertEqual(payload["segments"][0]["token_deltas"]["reasoning"], 5)
            self.assertEqual(payload["segments"][0]["token_deltas"]["total"], 25)

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

    def test_incomplete_segment_uses_now(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
            records = [
                spark_record("2026-07-10T21:00:00Z", "incomplete", "task_started"),
                spark_record("2026-07-10T21:00:10Z", "incomplete", "assistant", response_type="function_call"),
            ]
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "incomplete",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--session-file",
                str(session_file),
                "--now",
                "2026-07-10T21:13:00Z",
                "--json",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["segments"][0]["status"], "soft-limit")
            self.assertEqual(payload["segments"][0]["runtime_seconds"], 780.0)
            self.assertEqual(payload["status"], "soft-limit")

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

    def test_filename_match_ignores_unrelated_malformed_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            unrelated = root / "legacy_bad_record.jsonl"
            unrelated.write_text('{"session_id":"legacy","event"', encoding="utf-8")

            session_id = "session-match"
            session_file = root / "session-match-2026-07-10.jsonl"
            write_records(
                session_file,
                [
                    spark_record("2026-07-10T21:00:00Z", session_id, "task_started"),
                    spark_record("2026-07-10T21:00:10Z", session_id, "assistant", response_type="function_call"),
                    spark_record("2026-07-10T21:00:20Z", session_id, "task_complete"),
                ],
            )
            result = run_cli(
                "--session-id",
                session_id,
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--sessions-root",
                str(root),
                "--json",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["session_path"], str(session_file))

    def test_duplicate_filename_session_matches_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            session_id = "dup-session-id"
            first = root / f"{session_id}-a.jsonl"
            second = root / f"archive-{session_id}-b.jsonl"
            write_records(
                first,
                [spark_record("2026-07-10T21:00:00Z", session_id, "task_started")],
            )
            write_records(
                second,
                [spark_record("2026-07-10T21:00:10Z", session_id, "task_started")],
            )
            result = run_cli(
                "--session-id",
                session_id,
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--sessions-root",
                str(root),
                "--json",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("ambiguous", result.stderr.lower())

    def test_filename_matched_malformed_session_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            session_id = "malformed-session"
            malformed_session_file = root / f"{session_id}-session.jsonl"
            malformed_session_file.write_text('{"session_id":"malformed-session","event"', encoding="utf-8")
            result = run_cli(
                "--session-id",
                session_id,
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--sessions-root",
                str(root),
                "--json",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid json", result.stderr.lower())

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

    def test_cli_uses_top_level_native_payload_for_user_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
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
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "native-top-level-payload",
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

    def test_fallback_segmentation_attestation_then_work_with_compaction(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
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
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "fallback-compaction",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--session-file",
                str(session_file),
                "--json",
                "--now",
                "2026-07-10T21:01:00Z",
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(len(payload["segments"]), 3)
            self.assertEqual(payload["segments"][0]["tool_calls"], 0)
            self.assertEqual(payload["segments"][1]["tool_calls"], 1)
            self.assertEqual(payload["segments"][1]["context_compactions"], 1)
            self.assertEqual(payload["segments"][2]["tool_calls"], 0)
            self.assertEqual(payload["segments"][2]["context_compactions"], 0)
            self.assertEqual(payload["segments"][2]["full_suite_runs"], 0)
            self.assertEqual(payload["status"], "budget-exhausted")
            self.assertEqual(payload["return_status"], "budget-exhausted")
            self.assertIn("max_compactions", payload["hard_stop_reasons"])
            self.assertEqual(payload["attestation_source"], "turn_context")
            self.assertEqual(payload["attested_model"], "gpt-5.3-codex-spark")
            self.assertEqual(payload["segments"][1]["attestation_source"], "turn_context")
            self.assertEqual(payload["segments"][1]["attested_model"], "gpt-5.3-codex-spark")
            self.assertEqual(payload["segments"][1]["status"], "budget-exhausted")
            self.assertEqual(payload["segments"][1]["full_suite_runs"], 0)
            self.assertEqual(payload["segments"][1]["return_status"], "budget-exhausted")

    def test_fallback_segmentation_tool_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
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
            write_records(session_file, records)
            result = run_cli(
                "--session-id",
                "fallback-tool-isolation",
                "--requested-model",
                "gpt-5.3-codex-spark",
                "--budget-profile",
                "implementation",
                "--session-file",
                str(session_file),
                "--json",
                "--now",
                "2026-07-10T21:00:50Z",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(len(payload["segments"]), 2)
            self.assertEqual(payload["segments"][0]["tool_calls"], 1)
            self.assertEqual(payload["segments"][1]["tool_calls"], 2)
            self.assertEqual(payload["aggregate"]["tool_calls"], 3)


if __name__ == "__main__":
    unittest.main()
