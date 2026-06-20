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
        self.assertIn("Review command examples.", payload["prompt"])


if __name__ == "__main__":
    unittest.main()
