from __future__ import annotations

import json
import hashlib
import os
from unittest import mock
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import dispatch_codex_spark_worker as spark_worker

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "dispatch_codex_spark_worker.py"
REAL_CLI_JSONL_NO_RESPONSE_STREAM = """\
{"type":"thread.started","thread_id":"019f4e7a-8c17-7012-8003-c4de7ce7f123"}
{"type":"turn.started"}
{"type":"item.completed","item":{"id":"item_0","type":"agent_message","text":"Prelude response for stream ordering."}}
{"type":"item.completed","item":{"id":"item_1","type":"agent_message","text":"Parsed event stream smoke test."}}
{"type":"turn.completed","turn":{"usage":{"input_tokens":15235,"cached_input_tokens":14336,"output_tokens":1766,"reasoning_output_tokens":1664}}}
"""

REAL_CLI_JSONL_NO_AGENT_MESSAGE_STREAM = """\
{"type":"thread.started","thread_id":"019f4e7a-8c17-7012-8003-c4de7ce7f123"}
{"type":"turn.started"}
{"type":"turn.completed","turn":{"usage":{"input_tokens":15235,"cached_input_tokens":14336,"output_tokens":1766,"reasoning_output_tokens":1664}}}
"""


class DispatchCodexSparkWorkerTests(unittest.TestCase):
    SPARK_MODEL = "gpt-5.3-codex-spark"

    def _native_check_evidence(self, *, outcome: str = "native-subagent-unavailable") -> dict[str, object]:
        return {
            "outcome": outcome,
            "requested_model": self.SPARK_MODEL,
            "reason": "native tooling unavailable in test fixture",
        }

    def _build_fake_codex(self, tmp: Path, *, mode: str = "success") -> Path:
        fake = tmp / "codex"
        log = tmp / "codex_invocations.jsonl"
        tmp.mkdir(parents=True, exist_ok=True)
        fake.write_text(
            (
                "#!/usr/bin/env python3\n"
                "import json\n"
                "import os\n"
                "import sys\n"
                "from pathlib import Path\n\n"
                "log = Path(os.environ['CODEX_SPARK_FAKE_LOG'])\n"
                "record = {\n"
                "    'args': sys.argv[1:],\n"
                "    'cwd': os.getcwd(),\n"
                "    'stdin': sys.stdin.read(),\n"
                "    'mode': os.environ.get('CODEX_SPARK_FAKE_MODE', 'success'),\n"
                "}\n"
                "entries = []\n"
                "if log.exists():\n"
                "    entries = json.loads(log.read_text(encoding='utf-8'))\n"
                "entries.append(record)\n"
                "log.write_text(json.dumps(entries), encoding='utf-8')\n\n"
                "mode = os.environ.get('CODEX_SPARK_FAKE_MODE', 'success')\n"
                "if mode == 'malformed':\n"
                "    print('not-jsonl-output')\n"
                "    raise SystemExit(0)\n"
                "if mode == 'timeout':\n"
                "    import time\n"
                "    time.sleep(float(os.environ.get('CODEX_SPARK_FAKE_TIMEOUT_SECONDS', '3')))\n"
                "    print('{\"type\":\"turn.completed\",\"completion_state\":\"completed\",'\n"
                "          '\"usage\":{\"input_tokens\":9,\"cached_tokens\":3,\"output_tokens\":5,\"reasoning_tokens\":1}}')\n"
                "    raise SystemExit(0)\n"
                "if mode == 'partial_usage_then_complete':\n"
                "    print('{\"type\":\"turn.completed\",\"completion_state\":\"completed\",'\n"
                "          '\"usage\":{\"input_tokens\":1},'\n"
                "          '\"result\":{\"usage\":{\"input_tokens\":9,\"cached_tokens\":3,\"output_tokens\":5,\"reasoning_tokens\":1}}}')\n"
                "    raise SystemExit(0)\n"
                "if mode == 'subset_non_double_counting':\n"
                "    print('{\"type\":\"turn.completed\",\"completion_state\":\"completed\",'\n"
                "          '\"usage\":{\"input_tokens\":15235,\"cached_input_tokens\":14336,\"output_tokens\":1766,\"reasoning_output_tokens\":1664}}')\n"
                "    raise SystemExit(0)\n"
                "if mode == 'overreported_usage':\n"
                "    print('{\"type\":\"turn.completed\",\"completion_state\":\"completed\",'\n"
                "          '\"usage\":{\"input_tokens\":10,\"cached_tokens\":25,\"output_tokens\":5,\"reasoning_tokens\":99}}')\n"
                "    raise SystemExit(0)\n"
                "if mode == 'real_jsonl_stream_no_response':\n"
                "    print('OpenAI Codex v0.144.0')\n"
                f"    for line in '''\\\n"
                f"{REAL_CLI_JSONL_NO_RESPONSE_STREAM}'''.splitlines():\n"
                "        print(line)\n"
                "    raise SystemExit(0)\n"
                "if mode == 'no_agent_message_stream':\n"
                "    print('OpenAI Codex v0.144.0')\n"
                f"    for line in '''\\\n"
                f"{REAL_CLI_JSONL_NO_AGENT_MESSAGE_STREAM}'''.splitlines():\n"
                "        print(line)\n"
                "    raise SystemExit(0)\n"
                "if mode == 'mixed_noise':\n"
                "    print('unexpected banner noise')\n"
                "    print('{\"type\":\"turn.completed\",\"completion_state\":\"completed\",'\n"
                "          '\"usage\":{\"input_tokens\":9,\"cached_tokens\":3,\"output_tokens\":5,\"reasoning_tokens\":1}}')\n"
                "    raise SystemExit(0)\n"
                "if mode == 'mixed_noise_allowed':\n"
                "    print('OpenAI Codex v0.144.0')\n"
                "    print('{\"type\":\"turn.completed\",\"completion_state\":\"completed\",'\n"
                "          '\"usage\":{\"input_tokens\":9,\"cached_tokens\":3,\"output_tokens\":5,\"reasoning_tokens\":1}}')\n"
                "    raise SystemExit(0)\n"
                "if mode == 'model_mismatch':\n"
                "    print('{\"type\":\"turn.completed\",\"completion_state\":\"completed\",\"model\":\"gpt-5.6\",'\n"
                "          '\"usage\":{\"input_tokens\":9,\"cached_tokens\":3,\"output_tokens\":5,\"reasoning_tokens\":1}}')\n"
                "    raise SystemExit(0)\n"
                "if mode == 'fail':\n"
                "    sys.stderr.write('model unavailable: gpt-5.3-codex-spark\\n')\n"
                "    raise SystemExit(2)\n"
                "if mode == 'missing_usage':\n"
                "    print('{\"type\":\"turn.completed\",\"completion_state\":\"completed\"}')\n"
                "else:\n"
                "    print('{\"type\":\"turn.completed\",\"completion_state\":\"completed\",'\n"
                "          '\"usage\":{\"input_tokens\":9,\"cached_tokens\":3,\"output_tokens\":5,\"reasoning_tokens\":1}}')\n"
            ),
            encoding="utf-8",
        )
        fake.chmod(0o700)
        os.environ["CODEX_SPARK_FAKE_LOG"] = str(log)
        os.environ["CODEX_SPARK_FAKE_MODE"] = mode
        return fake

    def _run_bridge(
        self,
        *,
        tmp: Path,
        output: Path,
        audit: Path,
        mode: str = "success",
        timeout_seconds: int = 120,
        prompt_text: str = "prompt from stdin for spark bridge",
        return_file: Path | None = None,
        prompt_file: Path | None = None,
        env_overrides: dict[str, str] | None = None,
        native_check_evidence: dict[str, object] | None = None,
        include_native_check_evidence: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        fake = self._build_fake_codex(tmp, mode=mode)
        env = os.environ.copy()
        env["PATH"] = f"{tmp}:{env['PATH']}"
        env["CODEX_SPARK_FAKE_MODE"] = mode
        if env_overrides:
            env.update(env_overrides)
        if native_check_evidence is None:
            native_check_evidence = self._native_check_evidence()
        native_check = tmp / "native-check.json"
        native_check.write_text(json.dumps(native_check_evidence), encoding="utf-8")
        command = [
            sys.executable,
            str(SCRIPT),
            "--bead-id",
            "bead-spark",
            "--dispatch-id",
            "dispatch-spark",
            "--mode",
            "implementation-capable",
            "--lane",
            "validation",
            "--lane",
            "delegation-reporting",
            "--workdir",
            str(tmp),
            "--sandbox",
            "workspace-write",
            "--output",
            str(output),
            "--audit-file",
            str(audit),
            "--timeout-seconds",
            str(timeout_seconds),
        ]
        if include_native_check_evidence:
            command.extend(["--native-check-evidence", str(native_check)])
        if prompt_file is not None:
            command.extend(["--file", str(prompt_file)])
        if return_file is not None:
            command.extend(["--return-file", str(return_file)])
        return subprocess.run(
            command,
            input=prompt_text,
            cwd=str(ROOT),
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def _read_audit(self, path: Path) -> dict[str, object]:
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertTrue(lines)
        return json.loads(lines[-1])

    def test_bridge_dispatches_prompt_from_stdin_only_and_records_usage(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            output = tmp / "artifact.json"
            audit = tmp / "audit.jsonl"
            result = self._run_bridge(tmp=tmp, output=output, audit=audit, mode="success")
            self.assertEqual(result.returncode, 0)
            artifact = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(artifact["model"], self.SPARK_MODEL)
            self.assertEqual(artifact["telemetry_status"], "completed")
            self.assertEqual(artifact["completion_state"], "completed")
            self.assertEqual(artifact["requested_model"], self.SPARK_MODEL)
            self.assertEqual(artifact["actual_model"], self.SPARK_MODEL)
            self.assertIn("dispatch-spark", artifact["dispatch_id"])

            log = json.loads((tmp / "codex_invocations.jsonl").read_text(encoding="utf-8"))[-1]
            args = log["args"]
            stdin = log["stdin"]
            self.assertEqual(stdin, "prompt from stdin for spark bridge")
            self.assertEqual(args[:4], ["exec", "--model", self.SPARK_MODEL, "--sandbox"])
            self.assertIn("--json", args)
            self.assertEqual(args[-1], "-")
            self.assertIn("--model", args)
            self.assertIn(self.SPARK_MODEL, args)
            self.assertIn("--sandbox", args)
            self.assertEqual(log["cwd"], str(tmp))
            self.assertNotIn("prompt from stdin for spark bridge", " ".join(args))
            self.assertNotIn("5.6", " ".join(args))

            event = self._read_audit(audit)
            native_check = json.dumps(self._native_check_evidence())
            native_check_text = " ".join(native_check.split())
            native_check_hash = hashlib.sha256(native_check.encode("utf-8")).hexdigest()
            self.assertEqual(event["event_type"], "local_worker_dispatch")
            self.assertEqual(event["telemetry_status"], "completed")
            self.assertEqual(event["workerbee_actual_mode"], "implementation-capable")
            self.assertEqual(event["model"], self.SPARK_MODEL)
            self.assertEqual(event["requested_model"], self.SPARK_MODEL)
            self.assertEqual(event["actual_model"], self.SPARK_MODEL)
            self.assertEqual(event["native_check_outcome"], "native-subagent-unavailable")
            self.assertEqual(event["native_fallback_route"], "native-subagent-unavailable")
            self.assertEqual(event["native_check_evidence"], native_check_text)
            self.assertEqual(event["native_check_evidence_sha256"], native_check_hash)
            self.assertEqual(event["input_tokens"], 9)
            self.assertEqual(event["cached_tokens"], 3)
            self.assertEqual(event["output_tokens"], 5)
            self.assertEqual(event["reasoning_tokens"], 1)
            self.assertEqual(event["total_tokens"], 14)
            self.assertEqual(event["exit_status"], 0)
            self.assertEqual(event["completion_state"], "completed")
            self.assertIn("telemetry_source", event)
            self.assertNotIn("prompt", event)
            self.assertNotIn("response", event)
            self.assertIn("-", args)

    def test_bridge_prefers_prompt_file_over_stdin(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            output = tmp / "artifact.json"
            audit = tmp / "audit.jsonl"
            prompt_file = tmp / "prompt.txt"
            prompt_file.write_text("prompt from file path", encoding="utf-8")
            result = self._run_bridge(
                tmp=tmp,
                output=output,
                audit=audit,
                mode="success",
                prompt_text="",
                prompt_file=prompt_file,
            )
            self.assertEqual(result.returncode, 0)
            log = json.loads((tmp / "codex_invocations.jsonl").read_text(encoding="utf-8"))[-1]
            self.assertEqual(log["stdin"], "prompt from file path")
            self.assertNotIn(str(prompt_file), " ".join(log["args"]))

    def test_bridge_rejects_empty_prompt_file_even_when_stdin_has_text(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            output = tmp / "artifact.json"
            audit = tmp / "audit.jsonl"
            prompt_file = tmp / "prompt.txt"
            prompt_file.write_text("", encoding="utf-8")
            result = self._run_bridge(
                tmp=tmp,
                output=output,
                audit=audit,
                mode="success",
                prompt_text="this should be ignored",
                prompt_file=prompt_file,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("prompt text is required on stdin or in --file", result.stderr + result.stdout)

    def test_bridge_reports_missing_prompt_file(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            output = tmp / "artifact.json"
            audit = tmp / "audit.jsonl"
            missing_prompt = tmp / "missing.txt"
            result = self._run_bridge(
                tmp=tmp,
                output=output,
                audit=audit,
                prompt_file=missing_prompt,
                mode="success",
                prompt_text="",
            )
            self.assertNotEqual(result.returncode, 0)
            message = result.stderr + result.stdout
            self.assertIn("failed to read prompt file", message)
            self.assertIn(str(missing_prompt), message)

    def test_bridge_rejects_missing_native_check_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            output = tmp / "artifact.json"
            audit = tmp / "audit.jsonl"
            result = self._run_bridge(
                tmp=tmp,
                output=output,
                audit=audit,
                mode="success",
                include_native_check_evidence=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("native check evidence is required", result.stderr + result.stdout)

    def test_bridge_rejects_invalid_native_check_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            output = tmp / "artifact.json"
            audit = tmp / "audit.jsonl"
            evidence = self._native_check_evidence()
            evidence["outcome"] = "speed-up-needed"
            result = self._run_bridge(
                tmp=tmp,
                output=output,
                audit=audit,
                mode="success",
                native_check_evidence=evidence,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("native-check-evidence outcome must be one of", result.stderr + result.stdout)

    def test_bridge_rejects_native_check_evidence_with_wrong_model(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            output = tmp / "artifact.json"
            audit = tmp / "audit.jsonl"
            evidence = self._native_check_evidence()
            evidence["requested_model"] = "gpt-5.6"
            result = self._run_bridge(
                tmp=tmp,
                output=output,
                audit=audit,
                mode="success",
                native_check_evidence=evidence,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("requested_model must be gpt-5.3-codex-spark", result.stderr + result.stdout)

    def test_bridge_accepts_later_complete_usage_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            output = tmp / "artifact.json"
            audit = tmp / "audit.jsonl"
            result = self._run_bridge(tmp=tmp, output=output, audit=audit, mode="partial_usage_then_complete")
            self.assertEqual(result.returncode, 0)
            artifact = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(artifact["telemetry_status"], "completed")
            self.assertEqual(artifact["telemetry_missing_reason"], None)
            event = self._read_audit(audit)
            self.assertEqual(event["telemetry_status"], "completed")
            self.assertEqual(event["cached_tokens"], 3)
            self.assertEqual(event["output_tokens"], 5)
            self.assertEqual(event["input_tokens"], 9)
            self.assertEqual(event["total_tokens"], 14)

    def test_bridge_records_subset_usage_without_double_counting(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            output = tmp / "artifact.json"
            audit = tmp / "audit.jsonl"
            result = self._run_bridge(tmp=tmp, output=output, audit=audit, mode="subset_non_double_counting")
            self.assertEqual(result.returncode, 0)
            artifact = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(artifact["telemetry_status"], "completed")

            event = self._read_audit(audit)
            self.assertEqual(event["input_tokens"], 15235)
            self.assertEqual(event["cached_tokens"], 14336)
            self.assertEqual(event["output_tokens"], 1766)
            self.assertEqual(event["reasoning_tokens"], 1664)
            self.assertEqual(event["total_tokens"], 17001)
            self.assertLessEqual(event["cached_tokens"], event["input_tokens"])
            self.assertLessEqual(event["reasoning_tokens"], event["output_tokens"])

    def test_bridge_normalizes_overreported_usage_to_subset_relationships(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            output = tmp / "artifact.json"
            audit = tmp / "audit.jsonl"
            result = self._run_bridge(
                tmp=tmp,
                output=output,
                audit=audit,
                mode="overreported_usage",
            )
            self.assertEqual(result.returncode, 0)
            event = self._read_audit(audit)
            self.assertEqual(event["input_tokens"], 10)
            self.assertEqual(event["output_tokens"], 5)
            self.assertEqual(event["cached_tokens"], 10)
            self.assertEqual(event["reasoning_tokens"], 5)
            self.assertEqual(event["total_tokens"], 15)

    def test_classify_failure_reason_normalizes_escaped_newlines(self) -> None:
        reason = spark_worker._classify_failure_reason(
            returncode=2,
            stdout="",
            stderr="dispatch failed\\non a fallback path",
            events=[],
        )
        self.assertEqual(reason, "codex-error: dispatch failed")

    def test_bridge_parses_no_response_jsonl_stream(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            output = tmp / "artifact.json"
            audit = tmp / "audit.jsonl"
            result = self._run_bridge(tmp=tmp, output=output, audit=audit, mode="real_jsonl_stream_no_response")
            self.assertEqual(result.returncode, 0)
            artifact = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(artifact["telemetry_status"], "completed")
            self.assertEqual(artifact["completion_state"], "completed")

            event = self._read_audit(audit)
            self.assertEqual(event["telemetry_status"], "completed")
            self.assertEqual(event["input_tokens"], 15235)
            self.assertEqual(event["cached_tokens"], 14336)
            self.assertEqual(event["output_tokens"], 1766)
            self.assertEqual(event["reasoning_tokens"], 1664)
            self.assertEqual(event["total_tokens"], 17001)
            event_payload = json.dumps(event)
            artifact_payload = json.dumps(artifact)
            self.assertNotIn("Parsed event stream smoke test.", artifact_payload)
            self.assertNotIn("prompt", artifact_payload)
            self.assertNotIn("response", artifact_payload)
            self.assertNotIn("Parsed event stream smoke test.", event_payload)
            self.assertNotIn("prompt", event_payload)
            self.assertNotIn("response", event_payload)

    def test_bridge_rejects_mixed_unknown_jsonl_noise(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            output = tmp / "artifact.json"
            audit = tmp / "audit.jsonl"
        result = self._run_bridge(tmp=tmp, output=output, audit=audit, mode="mixed_noise")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAILED: codex-jsonl-parse-failed", result.stdout + result.stderr)
        self.assertNotIn('"telemetry_status": "completed"', output.read_text(encoding="utf-8"))

    def test_bridge_allows_mixed_known_jsonl_noise(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            output = tmp / "artifact.json"
            audit = tmp / "audit.jsonl"
            result = self._run_bridge(tmp=tmp, output=output, audit=audit, mode="mixed_noise_allowed")
            self.assertEqual(result.returncode, 0)
            artifact = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(artifact["telemetry_status"], "completed")

    def test_bridge_fails_closed_on_malformed_stdout_and_sanitized_audit(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            output = tmp / "artifact.json"
            audit = tmp / "audit.jsonl"
            result = self._run_bridge(tmp=tmp, output=output, audit=audit, mode="malformed")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("FAILED: codex-jsonl-parse-failed", result.stdout + result.stderr)
            artifact = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(artifact["telemetry_status"], "failed")
            self.assertEqual(artifact["telemetry_missing_reason"], "codex-jsonl-parse-failed")
            event = self._read_audit(audit)
            self.assertEqual(event["telemetry_missing_reason"], "codex-jsonl-parse-failed")
            self.assertNotIn("not-jsonl-output", json.dumps(event))
            self.assertNotIn("not-jsonl-output", event["telemetry_missing_reason"])

    def test_bridge_fails_closed_on_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            output = tmp / "artifact.json"
            audit = tmp / "audit.jsonl"
            result = self._run_bridge(
                tmp=tmp,
                output=output,
                audit=audit,
                mode="timeout",
                timeout_seconds=1,
                env_overrides={"CODEX_SPARK_FAKE_TIMEOUT_SECONDS": "3"},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("FAILED: codex-timeout-seconds-exceeded", result.stderr)
            artifact = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(artifact["telemetry_status"], "failed")
            self.assertEqual(artifact["telemetry_missing_reason"], "codex-timeout-seconds-exceeded")
            event = self._read_audit(audit)
            self.assertEqual(event["telemetry_status"], "failed")
            self.assertEqual(event["telemetry_missing_reason"], "codex-timeout-seconds-exceeded")
            self.assertEqual(event["exit_status"], 124)

    def test_bridge_fails_closed_when_usage_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            output = tmp / "artifact.json"
            audit = tmp / "audit.jsonl"
            result = self._run_bridge(tmp=tmp, output=output, audit=audit, mode="missing_usage")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("FAILED", result.stdout + result.stderr)
            artifact = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(artifact["telemetry_status"], "failed")
            self.assertIn("usage", artifact["telemetry_missing_reason"])

            event = self._read_audit(audit)
            self.assertEqual(event["telemetry_status"], "failed")
            self.assertIn("usage", event["telemetry_missing_reason"])
            self.assertEqual(event["workerbee_delegation_status"], "failed")
            self.assertEqual(event["completion_state"], "completed")

    def test_bridge_rejects_codex_model_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            output = tmp / "artifact.json"
            audit = tmp / "audit.jsonl"
            result = self._run_bridge(tmp=tmp, output=output, audit=audit, mode="model_mismatch")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("FAILED: codex-output-model-substitution:gpt-5.6", result.stdout + result.stderr)
            event = self._read_audit(audit)
            self.assertEqual(event["telemetry_status"], "failed")
            self.assertEqual(event["telemetry_missing_reason"], "codex-output-model-substitution:gpt-5.6")
            self.assertEqual(event["actual_model"], "gpt-5.6")
            self.assertEqual(event["requested_model"], self.SPARK_MODEL)

    def test_bridge_fails_closed_on_model_mismatch_or_child_error_and_no_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            output = tmp / "artifact.json"
            audit = tmp / "audit.jsonl"
            result = self._run_bridge(tmp=tmp, output=output, audit=audit, mode="fail")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("FAILED", result.stdout + result.stderr)
            self.assertIn("codex-spark-model-unavailable", (result.stderr or "").lower())
            event = self._read_audit(audit)
            self.assertEqual(event["telemetry_status"], "failed")
            self.assertIn("codex-spark-model-unavailable", event["telemetry_missing_reason"])
            self.assertEqual(event["telemetry_source"], "codex-spark-worker-bridge")
            self.assertEqual(event["model"], self.SPARK_MODEL)
            self.assertNotIn("5.6", (result.stderr or ""))

            log = json.loads((tmp / "codex_invocations.jsonl").read_text(encoding="utf-8"))[-1]
            args = log["args"]
            self.assertEqual(args[:4], ["exec", "--model", self.SPARK_MODEL, "--sandbox"])
            self.assertIn("--json", args)
            self.assertEqual(args[-1], "-")
            self.assertNotEqual(log["args"][1], "run")
            self.assertNotIn("5.6", " ".join(args))

    def test_bridge_writes_final_agent_message_to_return_file(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            output = tmp / "artifact.json"
            return_file = tmp / "agent-message.txt"
            audit = tmp / "audit.jsonl"
            result = self._run_bridge(
                tmp=tmp,
                output=output,
                audit=audit,
                return_file=return_file,
                mode="real_jsonl_stream_no_response",
            )
            self.assertEqual(result.returncode, 0)
            artifact = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(artifact["telemetry_status"], "completed")
            self.assertEqual(artifact["telemetry_missing_reason"], None)
            self.assertEqual(return_file.read_text(encoding="utf-8"), "Parsed event stream smoke test.")

    def test_bridge_sanitized_artifacts_when_return_file_is_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            output = tmp / "artifact.json"
            return_file = tmp / "agent-message.txt"
            audit = tmp / "audit.jsonl"
            result = self._run_bridge(
                tmp=tmp,
                output=output,
                audit=audit,
                return_file=return_file,
                mode="real_jsonl_stream_no_response",
            )
            self.assertEqual(result.returncode, 0)
            artifact_payload = output.read_text(encoding="utf-8")
            self.assertNotIn("Parsed event stream smoke test.", artifact_payload)
            self.assertNotIn("prompt", artifact_payload)
            self.assertNotIn("response", artifact_payload)
            self.assertEqual(return_file.read_text(encoding="utf-8"), "Parsed event stream smoke test.")
            event = self._read_audit(audit)
            event_payload = json.dumps(event)
            self.assertNotIn("Parsed event stream smoke test.", event_payload)
            self.assertNotIn("prompt", event_payload)
            self.assertNotIn("response", event_payload)

    def test_bridge_no_response_stream_fails_only_when_return_file_requested(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            output = tmp / "artifact.json"
            audit = tmp / "audit.jsonl"
            default = self._run_bridge(tmp=tmp, output=output, audit=audit, mode="no_agent_message_stream")
            self.assertEqual(default.returncode, 0)
            artifact = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(artifact["telemetry_status"], "completed")

            return_file = tmp / "return.txt"
            with_return_file = self._run_bridge(
                tmp=tmp,
                output=output,
                audit=audit,
                mode="no_agent_message_stream",
                return_file=return_file,
            )
            self.assertNotEqual(with_return_file.returncode, 0)
            self.assertIn("FAILED: codex-output-missing-final-agent-message", with_return_file.stderr + with_return_file.stdout)
            self.assertFalse(return_file.exists())
            event = self._read_audit(audit)
            self.assertEqual(event["telemetry_status"], "failed")
            self.assertEqual(event["telemetry_missing_reason"], "codex-output-missing-final-agent-message")

    def test_write_text_atomically_is_atomic_on_replace_failure(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            tmp = Path(workdir)
            target = tmp / "return.txt"
            with mock.patch("dispatch_codex_spark_worker.os.replace", side_effect=OSError("blocked")):
                with self.assertRaises(OSError):
                    spark_worker._write_text_atomically(target, "should stay partial-proof")
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
