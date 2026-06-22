from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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


if __name__ == "__main__":
    unittest.main()
