from __future__ import annotations

import subprocess
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_operator_handoff import validate_text, validate_continuation_state  # noqa: E402


SCOPED_BASE = """# Operator Handoff Packet
- Next executable Bead: complex-work-orchestration-bpm4
- Why it is next: v107 child stopped but parent preparation remains authorized
- Exact command/resume: python -B .orchestration-audit/v109/verify_v109.py
- Execution prompt: Continue zero-model preparation and preserve the paid stop.
- What must NOT run yet: no fresh SB-A paid attempt under the exhausted grant
- Commit/push status: not requested
- Validation status: providerless preparation verified
- Escalation rule: request only a precise uncovered paid authority delta
- Stopped operation: v107 SB-A paid child
- Stop scope: child
- Continuation disposition: continue-authorized
- Already-authorized next action: verify v109 providerless preparation
- Authority delta required: fresh SB-A qualification and pair, after gates
"""

SCOPED_STATE = {
    "version": 1,
    "stopped_operation": "v107 SB-A paid child",
    "stop_scope": "child",
    "authorized_next_action": "verify v109 providerless preparation",
    "authority_delta_required": "fresh SB-A qualification and pair, after gates",
}


class ValidateOperatorHandoffTests(unittest.TestCase):
    def test_scoped_child_stop_keeps_authorized_parent_work(self) -> None:
        self.assertEqual(
            validate_text(SCOPED_BASE, continuation_state=SCOPED_STATE), []
        )

    def test_scoped_state_rejects_false_generic_approval_handoff(self) -> None:
        false_stop = SCOPED_BASE.replace(
            "- Continuation disposition: continue-authorized",
            "- Continuation disposition: material-decision",
        ).replace(
            "- Already-authorized next action: verify v109 providerless preparation",
            "- Already-authorized next action: none",
        )
        errors = validate_text(false_stop, continuation_state=SCOPED_STATE)
        self.assertIn("handoff omitted an already-authorized next action", errors)

    def test_scoped_handoff_rejects_ask_as_next_command(self) -> None:
        text = SCOPED_BASE.replace(
            "- Exact command/resume: python -B .orchestration-audit/v109/verify_v109.py",
            "- Exact command/resume: ask for generic approval to proceed",
        )
        self.assertIn(
            "continue-authorized cannot hand off a generic approval request",
            validate_text(text, require_scoped_continuation=True),
        )

    def test_precise_material_decision_only_when_no_authorized_action(self) -> None:
        text = SCOPED_BASE.replace(
            "- Continuation disposition: continue-authorized",
            "- Continuation disposition: material-decision",
        ).replace(
            "- Already-authorized next action: verify v109 providerless preparation",
            "- Already-authorized next action: none",
        )
        state = {**SCOPED_STATE, "authorized_next_action": None}
        self.assertEqual(validate_text(text, continuation_state=state), [])
        self.assertIn(
            "material-decision requires a precise authority delta",
            validate_text(text.replace(
                "fresh SB-A qualification and pair, after gates", "approval needed"
            ), require_scoped_continuation=True),
        )

    def test_child_stop_cannot_complete_parent(self) -> None:
        text = SCOPED_BASE.replace(
            "- Continuation disposition: continue-authorized",
            "- Continuation disposition: complete",
        ).replace(
            "- Already-authorized next action: verify v109 providerless preparation",
            "- Already-authorized next action: none",
        ).replace(
            "- Authority delta required: fresh SB-A qualification and pair, after gates",
            "- Authority delta required: none",
        )
        self.assertIn(
            "child or path stop cannot complete the parent",
            validate_text(text, require_scoped_continuation=True),
        )

    def test_malformed_continuation_state_fails_controlled(self) -> None:
        for state in (
            {**SCOPED_STATE, "version": True},
            {**SCOPED_STATE, "stop_scope": []},
            {**SCOPED_STATE, "authorized_next_action": {}},
            {**SCOPED_STATE, "authority_delta_required": 0},
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
            state.write_text(json.dumps({**SCOPED_STATE, "authorized_next_action": None}), encoding="utf-8")
            bad = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("handoff authority delta disagrees", bad.stderr)

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
