from __future__ import annotations

import json
import contextlib
import io
import subprocess
import sys
import unittest
import uuid
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "authorize_sol_breakfix.py"
sys.path.insert(0, str(ROOT / "scripts"))
import authorize_sol_breakfix as breakfix  # noqa: E402


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


class AuthorizeSolBreakfixTests(unittest.TestCase):
    def assert_non_dry_refusal(self, args: list[str], message: str) -> None:
        effects = Mock()
        effects.audit.side_effect = lambda payload: payload
        control = [arg for arg in self.common_args() if arg != "--dry-run"]
        control += ["--allow-sol-breakfix", "--waiver-reason", "EXAMPLE incident"]
        with patch.object(breakfix.subprocess, "run", effects.update), \
                patch.object(breakfix, "record_audit_event", effects.audit), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with patch.object(sys, "argv", [str(SCRIPT), *control]):
                breakfix.main()
            self.assertEqual([call[0] for call in effects.mock_calls], ["update", "audit"])
            command = effects.update.call_args.args[0]
            self.assertEqual(command[:4], ["bd", "update", "--add-label", "sol-breakfix-approved"])
            self.assertEqual(command[-2:], ["--", "project-123"])
            self.assertEqual(effects.audit.call_args.args[0]["event_type"], "sol_breakfix_authorized")
            effects.reset_mock()
            with patch.object(sys, "argv", [str(SCRIPT), *[arg for arg in args if arg != "--dry-run"]]):
                with self.assertRaisesRegex(SystemExit, message):
                    breakfix.main()
            self.assertEqual(effects.mock_calls, [], "refused authorization reached update/audit")

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
        self.assert_non_dry_refusal([*self.common_args(), "--waiver-reason", "EXAMPLE incident"],
                                    "forbidden without --allow-sol-breakfix")

    def test_requires_waiver_reason(self) -> None:
        result = run_cli("--allow-sol-breakfix", *self.common_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--waiver-reason", result.stderr)
        self.assert_non_dry_refusal(["--allow-sol-breakfix", *self.common_args()], "--waiver-reason")

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
        nonce, readable = payload["dispatch_id"].split(".", 1)
        parsed_nonce = uuid.UUID(nonce)
        self.assertEqual(str(parsed_nonce), nonce)
        self.assertEqual(parsed_nonce.version, 4)
        self.assertRegex(readable, r"\Adispatch-sol-breakfix-project-123-\d{8}T\d{6}Z\Z")
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
        self.assert_non_dry_refusal(["--allow-sol-breakfix", *args, "--waiver-reason", "EXAMPLE incident"],
                                    "cannot outlive its authorized Bead")
        for field in ("--operator-approval-ref", "--scope", "--expires-after-bead"):
            with self.subTest(empty_field=field):
                empty = self.common_args()
                empty[empty.index(field) + 1] = " "
                self.assert_non_dry_refusal(["--allow-sol-breakfix", *empty, "--waiver-reason", "EXAMPLE incident"],
                                            "cannot outlive" if field == "--expires-after-bead" else "must be non-empty")


if __name__ == "__main__":
    unittest.main()
