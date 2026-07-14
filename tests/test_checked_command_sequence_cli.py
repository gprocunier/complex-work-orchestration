from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_checked_command_sequence.py"


def command_spec(cwd: Path, command_id: str, *argv: str, **updates):
    value = {
        "spec_type": "cwo-checked-command-spec",
        "version": 1,
        "command_id": command_id,
        "mode": "argv",
        "argv": list(argv),
        "cwd": str(cwd),
        "env": {},
        "inherit_environment": True,
        "stdin": None,
        "source": None,
        "preflights": [],
        "mutation_intent": "none",
        "allowed_paths": [],
        "timeout_seconds": 10,
    }
    value.update(updates)
    return value


def sequence_spec(cwd: Path, commands: list[dict]):
    return {
        "spec_type": "cwo-checked-command-sequence-spec",
        "version": 1,
        "sequence_id": "cli-sequence",
        "packet_id": "cli-packet",
        "work_plan_sha256": "a" * 64,
        "workdir": str(cwd),
        "commands": commands,
    }


class CheckedCommandSequenceCliTests(unittest.TestCase):
    def run_cli(self, spec_path: Path, state_path: Path, output_path: Path | None = None):
        argv = [sys.executable, str(SCRIPT), str(spec_path), "--state", str(state_path)]
        if output_path is not None:
            argv.extend(["--output", str(output_path)])
        return subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, check=False)

    def write_spec(self, root: Path, value: object) -> Path:
        target = root / "sequence.json"
        target.write_text(json.dumps(value), encoding="utf-8")
        return target

    def test_real_all_success_writes_matching_result_and_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec_path = self.write_spec(
                root,
                sequence_spec(
                    root,
                    [
                        command_spec(root, "one", "/usr/bin/true"),
                        command_spec(root, "two", "/usr/bin/true"),
                    ],
                ),
            )
            state_path = root / "state.json"
            output_path = root / "result.json"
            completed = self.run_cli(spec_path, state_path, output_path)

            result = json.loads(output_path.read_text(encoding="utf-8"))
            state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result, state)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["completed_count"], 2)

    def test_malformed_json_exits_two_with_blocked_receipt_and_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec_path = root / "sequence.json"
            spec_path.write_text("{not-json", encoding="utf-8")
            state_path = root / "state.json"
            completed = self.run_cli(spec_path, state_path)

            result = json.loads(completed.stdout)
            state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(result, state)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["failure_class"], "invalid-sequence-spec")
        self.assertNotIn("Traceback", completed.stderr)

    def test_middle_failure_prevents_later_sentinel(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sentinel = root / "sentinel"
            spec_path = self.write_spec(
                root,
                sequence_spec(
                    root,
                    [
                        command_spec(root, "before", "/usr/bin/true"),
                        command_spec(root, "fail", "/usr/bin/false"),
                        command_spec(
                            root,
                            "sentinel",
                            "/usr/bin/touch",
                            str(sentinel),
                            mutation_intent="workspace-scoped",
                            allowed_paths=["sentinel"],
                        ),
                    ],
                ),
            )
            state_path = root / "state.json"
            completed = self.run_cli(spec_path, state_path)

            result = json.loads(completed.stdout)
        self.assertEqual(completed.returncode, 1)
        self.assertFalse(sentinel.exists())
        self.assertEqual(result["failed_command_id"], "fail")
        self.assertEqual(result["completed_count"], 1)

    def test_out_of_scope_mutation_quarantines(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            writer = root / "writer.py"
            writer.write_text("from pathlib import Path\nPath('escaped.txt').write_text('x')\n", encoding="utf-8")
            spec_path = self.write_spec(
                root,
                sequence_spec(
                    root,
                    [
                        command_spec(
                            root,
                            "escape",
                            sys.executable,
                            str(writer),
                            mutation_intent="workspace-scoped",
                            allowed_paths=["allowed.txt"],
                        )
                    ],
                ),
            )
            state_path = root / "state.json"
            completed = self.run_cli(spec_path, state_path)

            result = json.loads(completed.stdout)
        self.assertEqual(completed.returncode, 3)
        self.assertEqual(result["status"], "quarantined")
        self.assertEqual(result["failure_class"], "command-quarantined")
        self.assertEqual(result["completed_count"], 0)

    def test_stdout_mode_emits_one_json_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec_path = self.write_spec(
                root,
                sequence_spec(root, [command_spec(root, "one", "/usr/bin/true")]),
            )
            completed = self.run_cli(spec_path, root / "state.json")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["status"], "passed")

    def test_output_is_atomic_and_leaves_no_temp_siblings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec_path = self.write_spec(
                root,
                sequence_spec(root, [command_spec(root, "one", "/usr/bin/true")]),
            )
            output_path = root / "result.json"
            completed = self.run_cli(spec_path, root / "state.json", output_path)

            leftovers = list(root.glob(f".{output_path.name}.*"))
            result = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
