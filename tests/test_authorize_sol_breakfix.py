from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "authorize_sol_breakfix.py"


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


class AuthorizeSolBreakfixTests(unittest.TestCase):
    def common_args(self) -> list[str]:
        return [
            "--operator-approval-ref",
            "current-chat-turn",
            "--bead",
            "project-123",
            "--incident-kind",
            "self-hosting-orchestration",
            "--scope",
            "self-hosting incident repair",
            "--expires-after-bead",
            "project-123",
            "--dry-run",
        ]

    def test_requires_explicit_allow_flag(self) -> None:
        result = run_cli(*self.common_args(), "--waiver-reason", "worker harness incident")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("forbidden without --allow-sol-breakfix", result.stderr)

    def test_requires_waiver_reason(self) -> None:
        result = run_cli("--allow-sol-breakfix", *self.common_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--waiver-reason", result.stderr)

    def test_dry_run_emits_heavy_warning_and_auditable_fields(self) -> None:
        result = run_cli(
            "--allow-sol-breakfix",
            *self.common_args(),
            "--waiver-reason",
            "native Spark harness repeatedly crossed hard guards",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("WARNING", result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["event_type"], "sol_breakfix_authorized")
        self.assertTrue(payload["dispatch_id"].startswith("dispatch-sol-breakfix-project-123-"))
        self.assertEqual(payload["sol_breakfix_incident_kind"], "self-hosting-orchestration")
        self.assertTrue(payload["swimlane_violation"])
        self.assertTrue(payload["automatic_selection_forbidden"])
        self.assertTrue(payload["waiver_required"])
        self.assertEqual(payload["waiver_flags"], ["--allow-sol-breakfix"])
        self.assertEqual(payload["sol_breakfix_expiry"], "project-123")

    def test_expiry_cannot_outlive_authorized_bead(self) -> None:
        args = self.common_args()
        args[args.index("project-123", args.index("--expires-after-bead"))] = "project-456"
        result = run_cli(
            "--allow-sol-breakfix",
            *args,
            "--waiver-reason",
            "native Spark harness incident",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot outlive its authorized Bead", result.stderr)


if __name__ == "__main__":
    unittest.main()
