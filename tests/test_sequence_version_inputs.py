from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import checked_command_sequence as sequence
import run_checked_command_sequence as cli


def specification(workdir: Path, version: object) -> dict:
    return {
        "spec_type": sequence.SPEC_TYPE,
        "version": version,
        "sequence_id": "EXAMPLE_SEQUENCE_0001",
        "packet_id": "EXAMPLE_PACKET_0001",
        "work_plan_sha256": "a" * 64,
        "workdir": str(workdir),
        "commands": [
            {
                "spec_type": "cwo-checked-command-spec",
                "version": 1,
                "command_id": "EXAMPLE_COMMAND_0001",
                "mode": "argv",
                "argv": [sys.executable, "--version"],
                "cwd": str(workdir),
                "env": {},
                "inherit_environment": False,
                "stdin": None,
                "source": None,
                "preflights": [],
                "mutation_intent": "none",
                "allowed_paths": [],
                "timeout_seconds": 10,
            },
        ],
    }


class SequenceVersionInputTests(unittest.TestCase):
    def test_numeric_versions_normalize_execute_and_persist(self):
        original_command = sequence.execute_checked_command
        original_write = sequence._atomic_write
        with tempfile.TemporaryDirectory() as root:
            workdir = Path(root) / "EXAMPLE_WORK"
            workdir.mkdir()
            normalized = []
            hashes = []
            for version in (1, 1.0):
                with self.subTest(kind=type(version).__name__):
                    value = specification(workdir, version)
                    normal = sequence.normalize_sequence_spec(value)
                    normalized.append(normal)
                    self.assertIs(type(normal["version"]), int)
                    target = Path(root) / "EXAMPLE_STATE.json"
                    with patch.object(
                        sequence, "execute_checked_command", wraps=original_command
                    ) as command, patch.object(
                        sequence, "_atomic_write", wraps=original_write
                    ) as write:
                        result = sequence.execute_checked_command_sequence(
                            value, state_path=str(target)
                        )
                    command.assert_called_once()
                    self.assertEqual(command.call_args.args[0], normal["commands"][0])
                    self.assertEqual([call.args[1]["status"] for call in write.call_args_list],
                                     ["running", "passed"])
                    self.assertEqual(result["status"], "passed")
                    self.assertIs(result["execution_started"], True)
                    self.assertEqual(result["completed_count"], 1)
                    self.assertIsNone(result["failure_class"])
                    self.assertEqual(result["command_results"][0]["execution_status"], "passed")
                    self.assertEqual(result["command_results"][0]["exit_code"], 0)
                    self.assertIs(result["command_results"][0]["execution_started"], True)
                    self.assertTrue(result["command_results"][0]["diagnostics"]["stdout"].startswith("Python "))
                    self.assertIs(result["command_results"][0]["mutation_started"], False)
                    self.assertEqual(json.loads(target.read_text(encoding="utf-8")), result)
                    hashes.append(result["spec_sha256"])
            self.assertEqual(normalized[0], normalized[1])
            self.assertEqual(hashes[0], hashes[1])
        self.assertIs(sequence.execute_checked_command, original_command)
        self.assertIs(sequence._atomic_write, original_write)

    def test_invalid_versions_refuse_before_command_normalization_or_execution(self):
        original_normalize = sequence.normalize_command_spec
        original_command = sequence.execute_checked_command
        with tempfile.TemporaryDirectory() as root:
            workdir = Path(root) / "EXAMPLE_WORK"
            workdir.mkdir()
            for version in (False, True, 0, 2, 1.5, "1", None, [], {}):
                with self.subTest(version=version):
                    value = specification(workdir, version)
                    target = Path(root) / "EXAMPLE_REFUSAL.json"
                    with patch.object(
                        sequence, "normalize_command_spec", wraps=original_normalize
                    ) as normalize, patch.object(
                        sequence, "execute_checked_command", wraps=original_command
                    ) as command:
                        with self.assertRaisesRegex(
                            ValueError, "unsupported checked-command sequence type or version"
                        ):
                            sequence.normalize_sequence_spec(value)
                        result = sequence.execute_checked_command_sequence(
                            value, state_path=str(target)
                        )
                    normalize.assert_not_called()
                    command.assert_not_called()
                    self.assertEqual(result["status"], "blocked")
                    self.assertIs(result["execution_started"], False)
                    self.assertEqual(result["completed_count"], 0)
                    self.assertIsNone(result["failed_command_id"])
                    self.assertEqual(result["failure_class"], "invalid-sequence-spec")
                    self.assertIsNone(result["spec_sha256"])
                    self.assertEqual(result["command_results"], [])
                    self.assertEqual(json.loads(target.read_text(encoding="utf-8")), result)
        self.assertIs(sequence.normalize_command_spec, original_normalize)
        self.assertIs(sequence.execute_checked_command, original_command)

    def test_cli_numeric_and_boolean_versions_preserve_output_and_status(self):
        original_command = sequence.execute_checked_command
        original_argv = sys.argv
        with tempfile.TemporaryDirectory() as root:
            workdir = Path(root) / "EXAMPLE_WORK"
            workdir.mkdir()
            for version in (1, 1.0, False, True):
                for output_file in (False, True):
                    with self.subTest(version=version, output_file=output_file):
                        spec_path = Path(root) / "EXAMPLE_SPEC.json"
                        state = Path(root) / "EXAMPLE_STATE.json"
                        output = Path(root) / "EXAMPLE_OUTPUT.json"
                        spec_path.write_text(
                            json.dumps(specification(workdir, version)), encoding="utf-8"
                        )
                        argv = ["run_checked_command_sequence.py", str(spec_path), "--state", str(state)]
                        if output_file:
                            argv.extend(["--output", str(output)])
                        stdout = io.StringIO()
                        with patch.object(sys, "argv", argv), redirect_stdout(stdout), patch.object(
                            sequence, "execute_checked_command", wraps=original_command
                        ) as command:
                            with self.assertRaises(SystemExit) as stopped:
                                cli.main()
                        valid = type(version) is not bool
                        self.assertEqual(stopped.exception.code, 0 if valid else 2)
                        self.assertEqual(command.call_count, 1 if valid else 0)
                        if output_file:
                            self.assertEqual(stdout.getvalue(), "")
                            rendered = output.read_text(encoding="utf-8")
                        else:
                            rendered = stdout.getvalue()
                        result = json.loads(rendered)
                        self.assertEqual(result["status"], "passed" if valid else "blocked")
                        self.assertIs(result["execution_started"], valid)
                        self.assertEqual(result["completed_count"], 1 if valid else 0)
                        self.assertEqual(
                            result["failure_class"], None if valid else "invalid-sequence-spec"
                        )
                        self.assertEqual(json.loads(state.read_text(encoding="utf-8")), result)
        self.assertIs(sequence.execute_checked_command, original_command)
        self.assertIs(sys.argv, original_argv)

    def test_boolean_refusal_keeps_state_path_precedence_and_write_failure(self):
        with tempfile.TemporaryDirectory() as root:
            value = specification(Path(root), True)
            with patch.object(sequence, "execute_checked_command") as command, patch.object(
                sequence, "_atomic_write"
            ) as write:
                result = sequence.execute_checked_command_sequence(value, state_path="EXAMPLE_RELATIVE.json")
            self.assertEqual(result["failure_class"], "invalid-state-path")
            write.assert_not_called()
            command.assert_not_called()
            with patch.object(sequence, "execute_checked_command") as command, patch.object(
                sequence, "_atomic_write", side_effect=OSError("EXAMPLE_WRITE_FAILURE")
            ):
                result = sequence.execute_checked_command_sequence(
                    value, state_path=str(Path(root) / "EXAMPLE_STATE.json")
                )
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["failure_class"], "state-persistence-failed")
            self.assertIs(result["execution_started"], False)
            command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
