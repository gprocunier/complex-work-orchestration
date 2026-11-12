from __future__ import annotations

import io
import json
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import checked_command as command
import run_checked_command as cli


def specification(root: Path, **updates):
    value = {
        "spec_type": command.SPEC_TYPE,
        "version": 1,
        "command_id": "EXAMPLE_COMMAND_0001",
        "mode": "python-source",
        "argv": [],
        "cwd": str(root),
        "env": {},
        "inherit_environment": False,
        "stdin": None,
        "source": "print('EXAMPLE_READY_0001')\n",
        "preflights": [],
        "mutation_intent": "none",
        "allowed_paths": [],
        "timeout_seconds": 10,
    }
    value.update(updates)
    return value


class CheckedCommandInputRefusalTests(unittest.TestCase):
    def assert_refusal(self, result, linter):
        self.assertEqual(result["result_type"], command.RESULT_TYPE)
        self.assertIs(type(result["version"]), int)
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["preflight_status"], "failed")
        self.assertEqual(result["linter"], linter)
        self.assertEqual(result["failure_class"], "command-construction-failed")
        self.assertEqual(result["execution_status"], "not-started")
        self.assertIs(result["execution_started"], False)
        self.assertIs(result["mutation_started"], False)
        self.assertEqual(result["mutated_paths"], [])
        self.assertIs(result["quarantine_required"], False)
        for field in ("exit_code", "linted_sha256", "executed_sha256", "hash_match"):
            self.assertIsNone(result[field])
        self.assertIs(result["quoting_error_prevented"], True)
        self.assertEqual(result["avoided_retry_cycles"], 1)
        self.assertEqual(result["diagnostics"]["stdout"], "")
        self.assertIsInstance(result["diagnostics"]["stderr"], str)
        self.assertTrue(result["diagnostics"]["stderr"])
        self.assertLessEqual(len(result["diagnostics"]["stderr"]), 4096)

    def assert_success(self, result):
        self.assertEqual(result["preflight_status"], "passed")
        self.assertEqual(result["execution_status"], "passed")
        self.assertIs(result["execution_started"], True)
        self.assertIs(type(result["exit_code"]), int)
        self.assertEqual(result["exit_code"], 0)
        self.assertIs(result["hash_match"], True)
        self.assertIsNone(result["failure_class"])
        self.assertIs(result["mutation_started"], False)
        self.assertEqual(result["mutated_paths"], [])
        self.assertIs(result["quarantine_required"], False)
        self.assertEqual(result["diagnostics"]["stdout"], "EXAMPLE_READY_0001\n")
        self.assertEqual(result["diagnostics"]["stderr"], "")
        self.assertIs(type(result["version"]), int)
        self.assertEqual(result["version"], 1)

    def without_actions(self, operation):
        original_snapshot = command._snapshot
        original_temporary = command.tempfile.TemporaryDirectory
        original_run = command.subprocess.run
        try:
            with (
                patch.object(command, "_snapshot", side_effect=AssertionError("Unexpected snapshot.")) as snapshot,
                patch.object(command.tempfile, "TemporaryDirectory", side_effect=AssertionError("Unexpected command preparation.")) as temporary,
                patch.object(command.subprocess, "run", side_effect=AssertionError("Unexpected command execution.")) as run,
            ):
                result = operation()
                snapshot.assert_not_called()
                temporary.assert_not_called()
                run.assert_not_called()
        finally:
            self.assertIs(command._snapshot, original_snapshot)
            self.assertIs(command.tempfile.TemporaryDirectory, original_temporary)
            self.assertIs(command.subprocess.run, original_run)
        return result

    def run_cli(self, root, value):
        spec_path = root / "EXAMPLE_SPEC_0001.json"
        spec_path.write_text(json.dumps(value), encoding="utf-8")
        stdout = io.StringIO()
        code = 0
        with patch.object(sys, "argv", ["EXAMPLE_CHECKED_COMMAND", str(spec_path)]), redirect_stdout(stdout):
            try:
                cli.main()
            except SystemExit as exc:
                code = exc.code
        return json.loads(stdout.getvalue()), code

    def test_numeric_versions_normalize_and_run_a_real_command(self):
        with tempfile.TemporaryDirectory(prefix="EXAMPLE-checked-input-") as temporary:
            root = Path(temporary)
            for version in (1, 1.0):
                with self.subTest(version_type=type(version).__name__):
                    value = specification(root, version=version, preflights=[
                        {"kind": "json", "value": "null"},
                        {"kind": "json-policy", "value": '{"EXAMPLE_ENABLED": true}'},
                        {"kind": "regex", "value": r"EXAMPLE_[0-9]+"},
                    ])
                    normalized = command.normalize_command_spec(value)
                    self.assertIs(type(normalized["version"]), int)
                    self.assertEqual(normalized["version"], 1)
                    self.assert_success(command.execute_checked_command(value))
                    result, code = self.run_cli(root, value)
                    self.assert_success(result)
                    self.assertEqual(code, 0)

    def test_boolean_versions_are_refused_before_actions(self):
        with tempfile.TemporaryDirectory(prefix="EXAMPLE-checked-input-") as temporary:
            root = Path(temporary)
            for version in (False, True):
                with self.subTest(version=version):
                    value = specification(root, version=version)
                    with self.assertRaisesRegex(ValueError, "unsupported checked-command spec type or version"):
                        command.normalize_command_spec(value)
                    result = self.without_actions(lambda: command.execute_checked_command(value))
                    self.assert_refusal(result, "spec-validator")
                    result, code = self.without_actions(lambda: self.run_cli(root, value))
                    self.assert_refusal(result, "spec-validator")
                    self.assertEqual(code, 2)

    def test_native_regex_recursion_is_reported_before_actions(self):
        pattern = "(" * 600 + "EXAMPLE" + ")" * 600
        with self.assertRaises(RecursionError):
            re.compile(pattern)
        with tempfile.TemporaryDirectory(prefix="EXAMPLE-checked-input-") as temporary:
            root = Path(temporary)
            value = specification(root, preflights=[{"kind": "regex", "value": pattern}])
            self.assertEqual(command.normalize_command_spec(value)["preflights"], value["preflights"])
            result = self.without_actions(lambda: command.execute_checked_command(value))
            self.assert_refusal(result, "nested-language")
            result, code = self.without_actions(lambda: self.run_cli(root, value))
            self.assert_refusal(result, "nested-language")
            self.assertEqual(code, 2)

    def test_native_json_version_distinction_preserves_both_kinds(self):
        input_text = "[" * 10000 + "0" + "]" * 10000
        if sys.version_info >= (3, 14):
            parsed = json.loads(input_text)
            self.assertIs(type(parsed), list)
            self.assertEqual(len(parsed), 1)
            native_recursion = False
        else:
            with self.assertRaises(RecursionError):
                json.loads(input_text)
            native_recursion = True
        with tempfile.TemporaryDirectory(prefix="EXAMPLE-checked-input-") as temporary:
            root = Path(temporary)
            for kind in ("json", "json-policy"):
                with self.subTest(kind=kind, python=sys.version_info[:2]):
                    value = specification(root, preflights=[{"kind": kind, "value": input_text}])
                    self.assertEqual(command.normalize_command_spec(value)["preflights"], value["preflights"])
                    if native_recursion or kind == "json-policy":
                        result = self.without_actions(lambda: command.execute_checked_command(value))
                        self.assert_refusal(result, "nested-language")
                        if not native_recursion:
                            self.assertEqual(result["diagnostics"]["stderr"],
                                             "json-policy preflight requires an object")
                        result, code = self.without_actions(lambda: self.run_cli(root, value))
                        self.assert_refusal(result, "nested-language")
                        self.assertEqual(code, 2)
                    else:
                        self.assert_success(command.execute_checked_command(value))
                        result, code = self.run_cli(root, value)
                        self.assert_success(result)
                        self.assertEqual(code, 0)

    def test_existing_parser_refusals_keep_their_result_and_exit_behavior(self):
        with tempfile.TemporaryDirectory(prefix="EXAMPLE-checked-input-") as temporary:
            root = Path(temporary)
            for kind, input_text in (("json", "{"), ("json-policy", "{"), ("json-policy", "[]"), ("regex", "[")):
                with self.subTest(kind=kind, input_text=input_text):
                    value = specification(root, preflights=[{"kind": kind, "value": input_text}])
                    result = self.without_actions(lambda: command.execute_checked_command(value))
                    self.assert_refusal(result, "nested-language")
                    result, code = self.without_actions(lambda: self.run_cli(root, value))
                    self.assert_refusal(result, "nested-language")
                    self.assertEqual(code, 2)

    def test_refusal_observers_are_restored_before_a_real_command(self):
        with tempfile.TemporaryDirectory(prefix="EXAMPLE-checked-input-") as temporary:
            root = Path(temporary)
            value = specification(root, version=True)
            self.assert_refusal(self.without_actions(lambda: command.execute_checked_command(value)), "spec-validator")
            self.assert_success(command.execute_checked_command(specification(root)))


if __name__ == "__main__":
    unittest.main()
