from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from close_bead_with_summary import execute, render_closure_summary  # noqa: E402


def args(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "bead": "complex-work-orchestration-abc",
        "disposition": "completed",
        "why": "policy helper added",
        "decision": ["close reason stays terse"],
        "evidence": ["python -m unittest tests/test_close_bead_with_summary.py"],
        "residual_risk": ["none known"],
        "follow_up": ["none"],
        "close": False,
        "close_reason": None,
        "dry_run": False,
        "json": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class CloseBeadWithSummaryTests(unittest.TestCase):
    def test_render_summary_uses_real_newlines(self) -> None:
        summary = render_closure_summary(
            bead="bd-1",
            disposition="completed",
            why="done",
            decisions=["first line\\nsecond line"],
            evidence=[],
            residual_risk=[],
            follow_up=[],
        )
        self.assertIn("first line\n  second line", summary)
        self.assertNotIn("\\n", summary)
        self.assertIn("Residual risk:\n- None recorded.", summary)

    def test_dry_run_does_not_call_bd(self) -> None:
        with patch("close_bead_with_summary.run_bd") as run_bd:
            result = execute(args(dry_run=True, close=True))
        run_bd.assert_not_called()
        self.assertTrue(result["dry_run"])
        self.assertFalse(result["comment_posted"])
        self.assertFalse(result["closed"])
        self.assertTrue(result["close_requested"])

    def test_comment_only_posts_summary(self) -> None:
        calls: list[list[str]] = []

        def fake_run_bd(command: list[str]) -> str:
            calls.append(command)
            return "ok"

        with patch("close_bead_with_summary.run_bd", side_effect=fake_run_bd):
            result = execute(args())

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0:2], ["comment", "complex-work-orchestration-abc"])
        self.assertIn("Closure summary:", calls[0][2])
        self.assertTrue(result["comment_posted"])
        self.assertFalse(result["closed"])

    def test_close_posts_comment_then_closes(self) -> None:
        calls: list[list[str]] = []

        def fake_run_bd(command: list[str]) -> str:
            calls.append(command)
            return "ok"

        with patch("close_bead_with_summary.run_bd", side_effect=fake_run_bd):
            result = execute(args(close=True, close_reason="completed: helper added"))

        self.assertEqual(calls[0][0], "comment")
        self.assertEqual(calls[1], ["close", "complex-work-orchestration-abc", "--reason", "completed: helper added"])
        self.assertTrue(result["comment_posted"])
        self.assertTrue(result["closed"])

    def test_missing_required_field_fails(self) -> None:
        with self.assertRaises(ValueError):
            execute(args(why=" "))


if __name__ == "__main__":
    unittest.main()
