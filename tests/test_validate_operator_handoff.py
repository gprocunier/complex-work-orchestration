from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_operator_handoff import validate_text, validate_continuation_state  # noqa: E402


SCOPED_BASE = """# Operator Handoff Packet
- Next executable Bead: complex-work-orchestration-bpm4
- Why it is next: providerless preparation can proceed independently
- Exact command/resume: python -B .orchestration-audit/v109/verify_v109.py
- Execution prompt: Continue providerless preparation.
- What must NOT run yet: no fresh SB-A paid attempt under the exhausted grant
- Commit/push status: not requested
- Validation status: providerless preparation verified
- Escalation rule: record the paid run's outstanding dependency
- Next action: verify v109 providerless preparation
- Waiting on: fresh SB-A qualification and pair, after gates
"""

SCOPED_STATE = {
    "version": 2,
    "next_action": "verify v109 providerless preparation",
    "waiting_on": "fresh SB-A qualification and pair, after gates",
}


class ValidateOperatorHandoffTests(unittest.TestCase):
    def test_scoped_dependency_keeps_independent_work(self) -> None:
        self.assertEqual(validate_text(SCOPED_BASE, require_scoped_continuation=True), [])
        self.assertEqual(
            validate_text(SCOPED_BASE, continuation_state=SCOPED_STATE), []
        )

    def test_scoped_state_rejects_missing_or_substituted_fields(self) -> None:
        for field, key, replacements in (
            ("Next action", "next_action", ("None", "check a different run")),
            ("Waiting on", "waiting_on", ("None", "a different qualification")),
        ):
            for replacement in replacements:
                with self.subTest(field=field, replacement=replacement):
                    changed = SCOPED_BASE.replace(
                        f"- {field}: {SCOPED_STATE[key]}", f"- {field}: {replacement}",
                    )
                    self.assertIn(
                        f"handoff {field} disagrees with continuation state",
                        validate_text(changed, continuation_state=SCOPED_STATE),
                    )

    def test_scoped_handoff_rejects_ask_as_next_command(self) -> None:
        text = SCOPED_BASE.replace(
            "- Exact command/resume: python -B .orchestration-audit/v109/verify_v109.py",
            "- Exact command/resume: ask for generic approval to proceed",
        )
        self.assertIn(
            "Exact command/resume must carry out the Next action",
            validate_text(text, require_scoped_continuation=True),
        )

    def test_scoped_wait_names_concrete_dependency(self) -> None:
        text = SCOPED_BASE.replace(f"Next action: {SCOPED_STATE['next_action']}", "Next action: None")
        state = {**SCOPED_STATE, "next_action": None}
        self.assertEqual(validate_text(text, continuation_state=state), [])
        self.assertIn(
            "field has no meaningful value: Waiting on",
            validate_text(text.replace(
                state["waiting_on"], "approval needed"
            ), require_scoped_continuation=True),
        )

    def test_work_without_dependency_can_continue(self) -> None:
        text = SCOPED_BASE.replace(
            f"Waiting on: {SCOPED_STATE['waiting_on']}", "Waiting on: `None`",
        )
        self.assertEqual(validate_text(text, require_scoped_continuation=True), [])
        self.assertEqual(validate_text(text, continuation_state={**SCOPED_STATE, "waiting_on": None}), [])

    def test_scoped_handoff_without_next_action_or_dependency_needs_source_state(self) -> None:
        text = SCOPED_BASE.replace(
            f"Next action: {SCOPED_STATE['next_action']}", "Next action: None",
        ).replace(f"Waiting on: {SCOPED_STATE['waiting_on']}", "Waiting on: None")
        self.assertIn(
            "a scoped handoff with no Next action or Waiting on requires continuation state",
            validate_text(text, require_scoped_continuation=True),
        )
        self.assertIn(
            "handoff Next action disagrees with continuation state",
            validate_text(text, continuation_state=SCOPED_STATE),
        )
        self.assertEqual(validate_text(text, continuation_state={
            "version": 2, "next_action": None, "waiting_on": None,
        }), [])

    def test_scoped_mode_needs_both_new_fields(self) -> None:
        base = SCOPED_BASE.split("- Next action:")[0]
        self.assertEqual(validate_text(base), [])
        self.assertEqual(validate_text(base, require_scoped_continuation=True), [
            "missing field: Next action", "missing field: Waiting on",
        ])

    def test_malformed_continuation_state_fails_controlled(self) -> None:
        for state in (
            {**SCOPED_STATE, "version": True},
            {**SCOPED_STATE, "version": 1},
            {**SCOPED_STATE, "next_action": {}},
            {**SCOPED_STATE, "waiting_on": 0},
            {**SCOPED_STATE, "waiting_on": "approval needed"},
            {**SCOPED_STATE, "unexpected": 1},
        ):
            with self.subTest(state=state):
                self.assertTrue(validate_continuation_state(state))
                self.assertTrue(validate_text(SCOPED_BASE, continuation_state=state))

    def test_cli_checks_source_derived_continuation_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            handoff = Path(temp_dir) / "handoff.md"
            state = Path(temp_dir) / "state.json"
            handoff.write_text(SCOPED_BASE, encoding="utf-8")
            state.write_text(json.dumps(SCOPED_STATE), encoding="utf-8")
            command = [
                sys.executable, str(ROOT / "scripts" / "validate_operator_handoff.py"),
                "--continuation-state", str(state), str(handoff),
            ]
            good = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(good.returncode, 0, good.stderr)
            state.write_text(json.dumps({**SCOPED_STATE, "waiting_on": None}), encoding="utf-8")
            bad = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("handoff Waiting on disagrees", bad.stderr)

    def test_accepts_meaningful_packet(self) -> None:
        text = """# Operator Handoff Packet

- Next executable Bead: cwo-123
- Why it is next: highest priority ready validation issue
- Exact command/resume: python3 scripts/cwo.py continue --epic cwo-epic
- Execution prompt: Continue cwo-123 only and stop before blocked work.
- What must NOT run yet: no contractor-only lanes
- Commit/push status: committed and pushed, remote HEAD verified
- Validation status: repository validation passed
- Escalation rule: stop if validation cannot run
"""

        self.assertEqual(validate_text(text), [])

    def test_rejects_markdown_wrapped_placeholders(self) -> None:
        text = """# Operator Handoff Packet

- Next executable Bead: `<bead-id>`
- Why it is next: `<why>`
- Exact command/resume: `<copy-paste command>`
- Execution prompt: `<prompt>`
- What must NOT run yet: `<blocked>`
- Commit/push status: `<status>`
- Validation status: `<status>`
- Escalation rule: `<rule>`
"""

        errors = validate_text(text)

        self.assertIn("field has no meaningful value: Next executable Bead", errors)
        self.assertIn("field has no meaningful value: Exact command/resume", errors)
        self.assertIn("field has no meaningful value: Escalation rule", errors)

    def test_cli_rejects_template_packet(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "validate_operator_handoff.py"),
                str(ROOT / "templates" / "operator-handoff-packet.md"),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("field has no meaningful value", result.stderr)

    def test_cli_self_test(self) -> None:
        subprocess.check_call(
            [
                sys.executable,
                str(ROOT / "scripts" / "validate_operator_handoff.py"),
                "--self-test",
            ],
            cwd=ROOT,
        )

    def test_rejects_missing_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "handoff.md"
            path.write_text("- Commit/push status: pushed\n", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "validate_operator_handoff.py"),
                    str(path),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing field: Next executable Bead", result.stderr)


if __name__ == "__main__":
    unittest.main()
