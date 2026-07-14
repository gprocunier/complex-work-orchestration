from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import checked_command_sequence as sequence

HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None


def load_schema(name: str) -> dict:
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


def command_spec(cwd: str, **updates) -> dict:
    value = {
        "spec_type": "cwo-checked-command-spec",
        "version": 1,
        "command_id": "command-1",
        "mode": "argv",
        "argv": ["/usr/bin/true"],
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


def sequence_spec(cwd: str, **updates) -> dict:
    value = {
        "spec_type": sequence.SPEC_TYPE,
        "version": 1,
        "sequence_id": "sequence-1",
        "packet_id": "packet-1",
        "work_plan_sha256": "a" * 64,
        "workdir": cwd,
        "commands": [command_spec(cwd)],
    }
    value.update(updates)
    return value


def command_result(**updates) -> dict:
    value = {
        "result_type": "cwo-checked-command-result",
        "version": 1,
        "command_id": "command-1",
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


class CheckedCommandSequenceSchemaStructureTests(unittest.TestCase):
    def test_schema_contract_objects_are_closed_and_exact(self):
        spec_schema = load_schema("checked-command-sequence-spec.schema.json")
        result_schema = load_schema("checked-command-sequence-result.schema.json")

        self.assertFalse(spec_schema["additionalProperties"])
        self.assertEqual(set(spec_schema["required"]), set(spec_schema["properties"]))
        command = spec_schema["$defs"]["command"]
        self.assertFalse(command["additionalProperties"])
        self.assertEqual(set(command["required"]), set(command["properties"]))
        self.assertEqual(command["properties"]["mode"], {"const": "argv"})
        self.assertEqual(command["properties"]["source"], {"type": "null"})

        self.assertFalse(result_schema["additionalProperties"])
        self.assertEqual(set(result_schema["required"]), set(result_schema["properties"]))
        command_result_schema = result_schema["$defs"]["command_result"]
        self.assertFalse(command_result_schema["additionalProperties"])
        self.assertEqual(
            set(command_result_schema["required"]),
            set(command_result_schema["properties"]),
        )
        diagnostics = command_result_schema["properties"]["diagnostics"]
        self.assertFalse(diagnostics["additionalProperties"])


@unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is not installed in test environment")
class CheckedCommandSequenceSchemaValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from jsonschema import Draft202012Validator

        cls.spec_validator = Draft202012Validator(
            load_schema("checked-command-sequence-spec.schema.json")
        )
        cls.result_validator = Draft202012Validator(
            load_schema("checked-command-sequence-result.schema.json")
        )

    def assert_invalid(self, validator, value):
        self.assertTrue(list(validator.iter_errors(value)))

    def test_valid_spec_and_runtime_results_validate(self):
        with tempfile.TemporaryDirectory() as root:
            spec = sequence_spec(root)
            self.spec_validator.validate(spec)
            with patch.object(sequence, "execute_checked_command", return_value=command_result()):
                passed = sequence.execute_checked_command_sequence(spec)
            blocked = sequence.execute_checked_command_sequence(None)

        self.result_validator.validate(passed)
        self.result_validator.validate(blocked)

    def test_spec_rejects_contract_violations(self):
        with tempfile.TemporaryDirectory() as root:
            valid = sequence_spec(root)
            cases = []

            extra_outer = copy.deepcopy(valid)
            extra_outer["extra"] = True
            cases.append(extra_outer)

            extra_inner = copy.deepcopy(valid)
            extra_inner["commands"][0]["extra"] = True
            cases.append(extra_inner)

            non_argv = copy.deepcopy(valid)
            non_argv["commands"][0].update({"mode": "python-source", "argv": [], "source": "pass"})
            cases.append(non_argv)

            empty_commands = copy.deepcopy(valid)
            empty_commands["commands"] = []
            cases.append(empty_commands)

            bad_hash = copy.deepcopy(valid)
            bad_hash["work_plan_sha256"] = "ABC"
            cases.append(bad_hash)

            missing_allowed_path = copy.deepcopy(valid)
            missing_allowed_path["commands"][0]["mutation_intent"] = "workspace-scoped"
            cases.append(missing_allowed_path)

            for value in cases:
                with self.subTest(value=value):
                    self.assert_invalid(self.spec_validator, value)

    def test_result_rejects_contract_and_exit_evidence_violations(self):
        with tempfile.TemporaryDirectory() as root, patch.object(
            sequence, "execute_checked_command", return_value=command_result()
        ):
            valid = sequence.execute_checked_command_sequence(sequence_spec(root))

        cases = []
        extra = copy.deepcopy(valid)
        extra["extra"] = True
        cases.append(extra)

        missing = copy.deepcopy(valid)
        del missing["completed_count"]
        cases.append(missing)

        boolean_exit = copy.deepcopy(valid)
        boolean_exit["command_results"][0]["exit_code"] = True
        cases.append(boolean_exit)

        invalid_status = copy.deepcopy(valid)
        invalid_status["status"] = "complete"
        cases.append(invalid_status)

        missing_passed_identity = copy.deepcopy(valid)
        missing_passed_identity["spec_sha256"] = None
        cases.append(missing_passed_identity)

        for value in cases:
            with self.subTest(value=value):
                self.assert_invalid(self.result_validator, value)


if __name__ == "__main__":
    unittest.main()
