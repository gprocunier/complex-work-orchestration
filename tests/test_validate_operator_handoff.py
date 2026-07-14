from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_operator_handoff import validate_text  # noqa: E402


class ValidateOperatorHandoffTests(unittest.TestCase):
    def test_accepts_meaningful_packet(self) -> None:
        text = """# Operator Handoff Packet

- Recommended operator action: CONTINUE
- Action to send: Use $complex-work-orchestration to continue from Bead cwo-123.
- Next executable Bead: cwo-123
- Why it is next: highest priority ready validation issue
- What must NOT run yet: no contractor-only lanes
- Commit/push status: committed and pushed, remote HEAD verified
- Validation status: repository validation passed
- Escalation rule: stop if validation cannot run
"""

        self.assertEqual(validate_text(text), [])

    def test_rejects_markdown_wrapped_placeholders(self) -> None:
        text = """# Operator Handoff Packet

- Recommended operator action: `<CONTINUE|EXECUTE|GO_REQUIRED|DECIDE|PIVOT|STOP>`
- Action to send: `<exact message>`
- Next executable Bead: `<bead-id>`
- Why it is next: `<why>`
- What must NOT run yet: `<blocked>`
- Commit/push status: `<status>`
- Validation status: `<status>`
- Escalation rule: `<rule>`
"""

        errors = validate_text(text)

        self.assertIn("field has no meaningful value: Next executable Bead", errors)
        self.assertIn("field has no meaningful value: Action to send", errors)
        self.assertIn("field has no meaningful value: Escalation rule", errors)

    def test_rejects_unknown_or_ambiguous_action(self) -> None:
        text = """# Operator Handoff Packet

- Recommended operator action: CONTINUE or PIVOT
- Action to send: Continue from Bead cwo-123.
- Next executable Bead: cwo-123
- Why it is next: highest priority ready issue
- What must NOT run yet: blocked lanes
- Commit/push status: not requested
- Validation status: repository validation passed
- Escalation rule: stop if validation cannot run
"""

        self.assertIn(
            "Recommended operator action must be exactly one of: CONTINUE, DECIDE, EXECUTE, GO_REQUIRED, PIVOT, STOP",
            validate_text(text),
        )

    def test_stop_requires_no_next_bead(self) -> None:
        text = """# Operator Handoff Packet

- Recommended operator action: STOP
- Action to send: No action. Stop condition met.
- Next executable Bead: cwo-123
- Why it is next: stop condition met
- What must NOT run yet: all work
- Commit/push status: not requested
- Validation status: repository validation passed
- Escalation rule: reopen only for new evidence
"""

        self.assertIn("STOP requires Next executable Bead to be none", validate_text(text))

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
