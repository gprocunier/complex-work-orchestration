from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import checked_command_sequence as sequence


def command_spec(cwd: str, command_id: str, *argv: str, **updates):
    value = {
        "spec_type": "cwo-checked-command-spec",
        "version": 1,
        "command_id": command_id,
        "mode": "argv",
        "argv": list(argv) or [sys.executable, "--version"],
        "cwd": cwd,
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


def sequence_spec(cwd: str, commands: list[dict], **updates):
    value = {
        "spec_type": sequence.SPEC_TYPE,
        "version": 1,
        "sequence_id": "sequence-1",
        "packet_id": "packet-1",
        "work_plan_sha256": "a" * 64,
        "workdir": cwd,
        "commands": commands,
    }
    value.update(updates)
    return value


def command_result(command_id: str, **updates):
    value = {
        "result_type": "cwo-checked-command-result",
        "version": 1,
        "command_id": command_id,
        "spec_sha256": "b" * 64,
        "execution_status": "passed",
        "exit_code": 0,
        "execution_started": True,
        "mutation_started": False,
        "mutated_paths": [],
        "failure_class": None,
        "quarantine_required": False,
        "diagnostics": {"stdout": "", "stderr": ""},
    }
    value.update(updates)
    return value


class CheckedCommandSequenceTests(unittest.TestCase):
    def test_all_success_preserves_order(self):
        with tempfile.TemporaryDirectory() as root:
            spec = sequence_spec(root, [command_spec(root, "one"), command_spec(root, "two")])
            with patch.object(
                sequence,
                "execute_checked_command",
                side_effect=[command_result("one"), command_result("two")],
            ) as execute:
                result = sequence.execute_checked_command_sequence(spec)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["completed_count"], 2)
        self.assertEqual([call.args[0]["command_id"] for call in execute.call_args_list], ["one", "two"])

    def test_failed_check_prevents_commit_and_push(self):
        with tempfile.TemporaryDirectory() as root:
            commands = [command_spec(root, name, "git", name) for name in ("add", "check", "commit", "push")]
            spec = sequence_spec(root, commands)
            with patch.object(
                sequence,
                "execute_checked_command",
                side_effect=[command_result("add"), command_result("check", execution_status="failed", exit_code=2, failure_class="execution-failed")],
            ) as execute:
                result = sequence.execute_checked_command_sequence(spec)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure_class"], "command-failed")
        self.assertEqual(result["failed_command_id"], "check")
        self.assertEqual(result["completed_count"], 1)
        self.assertEqual(execute.call_count, 2)

    def test_invalid_outer_specs_block_without_execution(self):
        invalid = [None, {}, {"extra": True}]
        for value in invalid:
            with self.subTest(value=value), patch.object(sequence, "execute_checked_command") as execute:
                result = sequence.execute_checked_command_sequence(value)
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["failure_class"], "invalid-sequence-spec")
            execute.assert_not_called()

    def test_duplicate_command_ids_block(self):
        with tempfile.TemporaryDirectory() as root:
            spec = sequence_spec(root, [command_spec(root, "same"), command_spec(root, "same")])
            result = sequence.execute_checked_command_sequence(spec)
        self.assertEqual(result["failure_class"], "invalid-sequence-spec")

    def test_inner_spec_requires_exact_fields_argv_and_matching_cwd(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as other:
            cases = [
                command_spec(root, "extra", unexpected=True),
                command_spec(root, "source", mode="python-source", source="print(1)", argv=[]),
                command_spec(other, "cwd"),
            ]
            for command in cases:
                with self.subTest(command=command["command_id"]):
                    result = sequence.execute_checked_command_sequence(sequence_spec(root, [command]))
                    self.assertEqual(result["failure_class"], "invalid-sequence-spec")

    def test_invalid_exit_evidence_blocks(self):
        for exit_code in (None, True, "0"):
            with tempfile.TemporaryDirectory() as root, patch.object(
                sequence,
                "execute_checked_command",
                return_value=command_result("one", exit_code=exit_code),
            ):
                result = sequence.execute_checked_command_sequence(sequence_spec(root, [command_spec(root, "one")]))
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["failure_class"], "invalid-exit-evidence")

    def test_nonmapping_and_exception_results_block(self):
        for effect, failure in ((None, "invalid-command-result"), (OSError("boom"), "command-execution-exception")):
            with tempfile.TemporaryDirectory() as root, patch.object(
                sequence,
                "execute_checked_command",
                side_effect=effect if isinstance(effect, Exception) else None,
                return_value=effect,
            ):
                result = sequence.execute_checked_command_sequence(sequence_spec(root, [command_spec(root, "one")]))
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["failure_class"], failure)

    def test_timeout_and_quarantine_are_terminal(self):
        cases = [
            (command_result("one", execution_status="failed", exit_code=None, failure_class="execution-timeout"), "failed"),
            (command_result("one", execution_status="quarantined", quarantine_required=True, failure_class="scope-violation"), "quarantined"),
        ]
        for inner, status in cases:
            with tempfile.TemporaryDirectory() as root, patch.object(sequence, "execute_checked_command", return_value=inner):
                result = sequence.execute_checked_command_sequence(sequence_spec(root, [command_spec(root, "one"), command_spec(root, "two")]))
            self.assertEqual(result["status"], status)
            self.assertEqual(result["completed_count"], 0)

    def test_passed_result_with_failure_class_fails(self):
        with tempfile.TemporaryDirectory() as root, patch.object(
            sequence,
            "execute_checked_command",
            return_value=command_result("one", failure_class="contradiction"),
        ):
            result = sequence.execute_checked_command_sequence(sequence_spec(root, [command_spec(root, "one")]))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure_class"], "command-result-failure")

    def test_hash_is_stable_for_equivalent_normalized_spec(self):
        with tempfile.TemporaryDirectory() as root, patch.object(
            sequence, "execute_checked_command", return_value=command_result("one")
        ):
            spec = sequence_spec(root, [command_spec(root, "one")])
            first = sequence.execute_checked_command_sequence(copy.deepcopy(spec))
            second = sequence.execute_checked_command_sequence(copy.deepcopy(spec))
        self.assertEqual(first["spec_sha256"], second["spec_sha256"])
        self.assertEqual(len(first["spec_sha256"]), 64)

    def test_atomic_running_and_terminal_snapshots(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "state.json"
            spec = sequence_spec(root, [command_spec(root, "one"), command_spec(root, "two")])
            snapshots = []
            original = sequence._atomic_write

            def record(path, payload):
                snapshots.append(copy.deepcopy(payload))
                original(path, payload)

            with patch.object(sequence, "_atomic_write", side_effect=record), patch.object(
                sequence,
                "execute_checked_command",
                side_effect=[command_result("one"), command_result("two")],
            ):
                result = sequence.execute_checked_command_sequence(spec, state_path=str(target))
            persisted = json.loads(target.read_text())
        self.assertEqual([item["status"] for item in snapshots], ["running", "running", "passed"])
        self.assertEqual(persisted, result)

    def test_persistence_failure_prevents_next_command(self):
        with tempfile.TemporaryDirectory() as root, patch.object(
            sequence, "_atomic_write", side_effect=OSError("disk full")
        ), patch.object(
            sequence,
            "execute_checked_command",
            side_effect=[command_result("one"), command_result("two")],
        ) as execute:
            result = sequence.execute_checked_command_sequence(
                sequence_spec(root, [command_spec(root, "one"), command_spec(root, "two")]),
                state_path=str(Path(root) / "state.json"),
            )
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["failure_class"], "state-persistence-failed")
        self.assertEqual(execute.call_count, 1)

    def test_invalid_state_path_blocks_before_execution(self):
        with tempfile.TemporaryDirectory() as root, patch.object(sequence, "execute_checked_command") as execute:
            result = sequence.execute_checked_command_sequence(
                sequence_spec(root, [command_spec(root, "one")]), state_path="relative.json"
            )
        self.assertEqual(result["failure_class"], "invalid-state-path")
        execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
