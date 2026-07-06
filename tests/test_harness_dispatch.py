from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cwo_core.audit as audit_lib  # noqa: E402
from render_harness_dispatch import main as render_harness_main  # noqa: E402


class HarnessDispatchScriptTests(unittest.TestCase):
    def test_render_harness_dispatch_json(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "render_harness_dispatch.py"),
                "--environment",
                "connected-opencode-exemplar",
                "--harness",
                "opencode",
                "--role",
                "worker",
                "--bead",
                "cwo-test",
                "--agent",
                "cwo-review",
                "--no-audit",
                "--waiver-reason",
                "test harness render without audit",
                "--json",
                "Review command examples.",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        payload = json.loads(result.stdout)
        self.assertEqual(payload["environment"], "connected-opencode-exemplar")
        self.assertEqual(payload["harness"], "opencode")
        self.assertEqual(payload["role"], "worker")
        self.assertEqual(payload["bead_id"], "cwo-test")
        self.assertFalse(payload["execution_enabled"])
        self.assertEqual(payload["model_profile"], "rhoai-worker-qwen2-5-coder-32b-fp8")
        self.assertEqual(payload["model"], "rhoai/workerbee")
        self.assertEqual(payload["agent"], "cwo-review")
        self.assertTrue(payload["capability_requirements"]["supports_local_openai_compatible"])
        self.assertIn("--model rhoai/workerbee", payload["suggested_command"])
        self.assertIn("Review command examples.", payload["prompt"])

    def test_render_harness_dispatch_with_explicit_model_profile(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "render_harness_dispatch.py"),
                "--environment",
                "airgapped-rhoai",
                "--role",
                "worker",
                "--model-profile",
                "rhoai-worker-qwen2-5-coder-32b-fp8",
                "--no-audit",
                "--waiver-reason",
                "test harness render without audit",
                "--json",
                "Review command examples.",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        payload = json.loads(result.stdout)
        self.assertEqual(payload["environment"], "airgapped-rhoai")
        self.assertEqual(payload["harness"], "opencode")
        self.assertEqual(payload["model_profile"], "rhoai-worker-qwen2-5-coder-32b-fp8")
        self.assertEqual(payload["model_profile_details"]["huggingface_model_id"], "RedHatAI/Qwen2.5-Coder-32B-Instruct-FP8-dynamic")
        self.assertTrue(payload["capability_requirements"]["supports_local_openai_compatible"])

    def test_render_harness_dispatch_for_h200_candidate(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "render_harness_dispatch.py"),
                "--environment",
                "airgapped-rhoai-h200-nemotron",
                "--role",
                "architect",
                "--no-audit",
                "--waiver-reason",
                "test harness render without audit",
                "--json",
                "Review the disconnected enterprise plan.",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        payload = json.loads(result.stdout)
        self.assertEqual(payload["environment"], "airgapped-rhoai-h200-nemotron")
        self.assertEqual(payload["model_profile"], "rhoai-architect-nemotron-3-ultra-550b-a55b-fp8")
        self.assertEqual(payload["model"], "rhoai/architect-nemotron-ultra")
        self.assertEqual(payload["model_profile_details"]["promotion_status"], "candidate")
        self.assertIn("vLLM startup with required parser flags", payload["model_profile_details"]["benchmark_gate"])

    def test_render_harness_dispatch_rejects_model_and_profile(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "render_harness_dispatch.py"),
                "--environment",
                "airgapped-rhoai",
                "--role",
                "worker",
                "--model",
                "rhoai/custom",
                "--model-profile",
                "rhoai-worker-qwen2-5-coder-32b-fp8",
                "--no-audit",
                "--waiver-reason",
                "test harness render without audit",
                "--json",
                "Review command examples.",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mutually exclusive", result.stderr)

    def test_render_harness_dispatch_audits_without_prompt_body(self) -> None:
        original_audit = audit_lib.AUDIT_LOG
        original_argv = sys.argv[:]
        with tempfile.TemporaryDirectory() as tmpdir:
            tempdir = Path(tmpdir)
            try:
                audit_lib.AUDIT_LOG = tempdir / "audit.jsonl"
                sys.argv = [
                    "render_harness_dispatch.py",
                    "--environment",
                    "connected-opencode-exemplar",
                    "--harness",
                    "opencode",
                    "--role",
                    "worker",
                    "--bead",
                    "cwo-test",
                    "--agent",
                    "cwo-review",
                    "--json",
                    "Review command examples.",
                ]
                with contextlib.redirect_stdout(io.StringIO()):
                    render_harness_main()
                events = [json.loads(line) for line in audit_lib.AUDIT_LOG.read_text(encoding="utf-8").splitlines()]
                self.assertEqual(events[0]["event_type"], "harness_dispatch_rendered")
                self.assertEqual(events[0]["telemetry_kind"], "harness_render")
                self.assertFalse(events[0]["execution_enabled"])
                self.assertIn("prompt_sha256", events[0])
                self.assertNotIn("prompt", events[0])
                self.assertNotIn("suggested_command", events[0])
            finally:
                audit_lib.AUDIT_LOG = original_audit
                sys.argv = original_argv


if __name__ == "__main__":
    unittest.main()
