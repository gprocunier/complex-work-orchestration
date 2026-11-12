from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def load_cli(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


COMMAND = load_cli("run_checked_command")
SEQUENCE = load_cli("run_checked_command_sequence")


class CheckedCLIInputRefusalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.work = self.root / "EXAMPLE_WORK"
        self.work.mkdir()
        self.source = self.root / "EXAMPLE_SPEC.json"
        self.output = self.root / "EXAMPLE_RESULT.json"
        self.state = self.root / "EXAMPLE_STATE.json"
        self.marker = self.work / "EXAMPLE_ACTIONS.txt"
        self.script = self.root / "EXAMPLE_ACTION.py"
        self.script.write_text(
            "import sys\n"
            "from pathlib import Path\n"
            "with Path(sys.argv[1]).open('a', encoding='utf-8') as handle:\n"
            "    handle.write(sys.argv[2] + '\\n')\n"
            "print(sys.argv[2])\n"
            "raise SystemExit(int(sys.argv[3]))\n",
            encoding="utf-8",
        )

    def _spec(self, kind):
        command = {
            "spec_type": "cwo-checked-command-spec",
            "version": 1,
            "command_id": "EXAMPLE_FIRST",
            "mode": "argv",
            "argv": [sys.executable, str(self.script), self.marker.name, "EXAMPLE_FIRST", "0"],
            "cwd": str(self.work),
            "env": {},
            "inherit_environment": False,
            "stdin": None,
            "source": None,
            "preflights": [],
            "mutation_intent": "workspace-scoped",
            "allowed_paths": [self.marker.name],
            "timeout_seconds": 10,
        }
        if kind == "command":
            return command
        second = command | {
            "command_id": "EXAMPLE_SECOND",
            "argv": [sys.executable, str(self.script), self.marker.name, "EXAMPLE_SECOND", "0"],
        }
        return {
            "spec_type": "cwo-checked-command-sequence-spec",
            "version": 1,
            "sequence_id": "EXAMPLE_SEQUENCE",
            "packet_id": "EXAMPLE_PACKET",
            "work_plan_sha256": "a" * 64,
            "workdir": str(self.work),
            "commands": [command, second],
        }

    def _run(self, kind, output=None):
        for path in (self.output, self.state, self.marker):
            path.unlink(missing_ok=True)
        script = "run_checked_command" + ("_sequence" if kind == "sequence" else "") + ".py"
        args = [sys.executable, str(ROOT / "scripts" / script), str(self.source)]
        if kind == "sequence":
            args.extend(["--state", str(self.state)])
        if output is not None:
            args.extend(["--output", str(output)])
        return subprocess.run(
            args,
            cwd=self.root,
            env={
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONINTMAXSTRDIGITS": "4300",
            },
            capture_output=True,
            text=True,
            timeout=30,
        )

    def _report(self, process, output):
        self.assertEqual(process.stderr, "")
        if output is None:
            rendered = process.stdout
            self.assertFalse(self.output.exists())
        else:
            self.assertEqual(process.stdout, "")
            rendered = output.read_text(encoding="utf-8")
        result = json.loads(rendered)
        self.assertEqual(rendered, json.dumps(result, indent=2, sort_keys=True) + "\n")
        return result

    def _refusal(self, kind, result):
        self.assertIs(result["execution_started"], False)
        self.assertFalse(self.marker.exists())
        if kind == "command":
            self.assertEqual(result, COMMAND.execute_checked_command(None))
            self.assertEqual(result["preflight_status"], "failed")
            self.assertEqual(result["execution_status"], "not-started")
            self.assertEqual(result["failure_class"], "command-construction-failed")
            self.assertIs(result["mutation_started"], False)
            self.assertIsNone(result["exit_code"])
        else:
            self.assertEqual(result, SEQUENCE.execute_checked_command_sequence(None))
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["failure_class"], "invalid-sequence-spec")
            self.assertEqual(result["command_results"], [])
            self.assertEqual(result["completed_count"], 0)
            self.assertEqual(json.loads(self.state.read_text(encoding="utf-8")), result)
        self.assertEqual(list(self.root.glob(".EXAMPLE_*")), [])

    def _passed(self, kind, result):
        labels = ["EXAMPLE_FIRST"] + (["EXAMPLE_SECOND"] if kind == "sequence" else [])
        self.assertEqual(
            self.marker.read_text(encoding="utf-8"), "".join(label + "\n" for label in labels)
        )
        self.assertIs(result["execution_started"], True)
        if kind == "command":
            self.assertEqual(result["execution_status"], "passed")
            results = [result]
        else:
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["completed_count"], 2)
            self.assertEqual(json.loads(self.state.read_text(encoding="utf-8")), result)
            results = result["command_results"]
        self.assertEqual(
            [item["diagnostics"]["stdout"] for item in results],
            [label + "\n" for label in labels],
        )
        for item in results:
            self.assertEqual(item["exit_code"], 0)
            self.assertEqual(item["execution_status"], "passed")
            self.assertIs(item["execution_started"], True)
            self.assertIs(item["mutation_started"], True)
            self.assertEqual(item["mutated_paths"], [self.marker.name])
        self.assertEqual(list(self.root.glob(".EXAMPLE_*")), [])

    def test_actual_cli_input_failures_are_reported(self):
        for kind in ("command", "sequence"):
            for case in ("syntax", "utf8", "absent", "directory"):
                for output in (None, self.output):
                    with self.subTest(kind=kind, case=case, output=output is not None):
                        self.source = self.root / f"EXAMPLE_{case}.json"
                        if case == "directory":
                            self.source.mkdir(exist_ok=True)
                        elif case != "absent":
                            text = json.dumps(self._spec(kind))
                            suffix = b" EXAMPLE_INVALID_JSON" if case == "syntax" else bytes([255])
                            self.source.write_bytes(text.encode("utf-8") + suffix)
                        process = self._run(kind, output)
                        self.assertEqual(process.returncode, 2, process.stderr)
                        self._refusal(kind, self._report(process, output))

    def test_native_deep_json_uses_the_interpreter_parser(self):
        text = "[" * 10000 + "0" + "]" * 10000
        recursed = False
        try:
            parsed = json.loads(text)
        except RecursionError:
            recursed = True
        else:
            self.assertIsInstance(parsed, list)
        if sys.version_info[:2] == (3, 12):
            self.assertTrue(recursed)
        elif sys.version_info[:2] == (3, 14):
            self.assertFalse(recursed)
        self.source.write_text(text, encoding="utf-8")
        for kind in ("command", "sequence"):
            for output in (None, self.output):
                with self.subTest(kind=kind, output=output is not None):
                    process = self._run(kind, output)
                    self.assertEqual(process.returncode, 2, process.stderr)
                    self._refusal(kind, self._report(process, output))

    def test_native_integer_loaders_keep_parse_and_refusal_behavior(self):
        previous_limit = sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(4300)
            in_range = "1" * 4300
            parsed = json.loads(in_range)
            self.assertIs(type(parsed), int)
            self.assertEqual(parsed, (10 ** 4300 - 1) // 9)
            self.source.write_text(in_range, encoding="utf-8")
            for module in (COMMAND, SEQUENCE):
                with self.subTest(module=module.__name__, digits=4300):
                    loaded = module._load_spec(self.source)
                    self.assertIs(type(loaded), int)
                    self.assertEqual(loaded, parsed)
                    execute = (
                        module.execute_checked_command
                        if module is COMMAND
                        else module.execute_checked_command_sequence
                    )
                    self.assertEqual(execute(loaded), execute(None))
            over_limit = "1" * 4301
            with self.assertRaises(ValueError) as refusal:
                json.loads(over_limit)
            self.assertNotIsInstance(refusal.exception, json.JSONDecodeError)
            self.source.write_text(over_limit, encoding="utf-8")
            for module in (COMMAND, SEQUENCE):
                with self.subTest(module=module.__name__, digits=4301):
                    self.assertIsNone(module._load_spec(self.source))
        finally:
            sys.set_int_max_str_digits(previous_limit)

    def test_actual_native_integer_inputs_are_reported(self):
        for digits in (4300, 4301):
            self.source.write_text("1" * digits, encoding="utf-8")
            for kind in ("command", "sequence"):
                for output in (None, self.output):
                    with self.subTest(kind=kind, digits=digits, output=output is not None):
                        process = self._run(kind, output)
                        self.assertEqual(process.returncode, 2, process.stderr)
                        self._refusal(kind, self._report(process, output))

    def test_loader_boundary_and_unexpected_errors(self):
        self.source.write_text("null", encoding="utf-8")
        for module in (COMMAND, SEQUENCE):
            for failure in (OSError("EXAMPLE read failure"), UnicodeError("EXAMPLE decode failure")):
                with self.subTest(module=module.__name__, failure=type(failure).__name__):
                    with patch.object(module.Path, "read_text", side_effect=failure):
                        self.assertIsNone(module._load_spec(self.source))
            for failure in (
                json.JSONDecodeError("EXAMPLE parse failure", "", 0),
                ValueError("EXAMPLE integer conversion failure"),
                RecursionError("EXAMPLE recursion failure"),
            ):
                with self.subTest(module=module.__name__, failure=type(failure).__name__):
                    with patch.object(module.json, "loads", side_effect=failure):
                        self.assertIsNone(module._load_spec(self.source))
            for failure in (KeyboardInterrupt, SystemExit, RuntimeError):
                with self.subTest(module=module.__name__, failure=failure.__name__):
                    with patch.object(module.json, "loads", side_effect=failure):
                        with self.assertRaises(failure):
                            module._load_spec(self.source)

    def test_actual_valid_controls_preserve_numeric_versions_and_actions(self):
        for kind in ("command", "sequence"):
            for version in ("1", "1.0", "1e0"):
                for output in (None, self.output):
                    with self.subTest(kind=kind, version=version, output=output is not None):
                        text = json.dumps(self._spec(kind))
                        text = text.replace('"version": 1', f'"version": {version}')
                        self.source.write_text(text, encoding="utf-8")
                        process = self._run(kind, output)
                        self.assertEqual(process.returncode, 0, process.stderr)
                        result = self._report(process, output)
                        self._passed(kind, result)

    def test_actual_failed_and_quarantined_controls_keep_exit_selection(self):
        for kind in ("command", "sequence"):
            for quarantined in (False, True):
                with self.subTest(kind=kind, quarantined=quarantined):
                    spec = self._spec(kind)
                    command = spec if kind == "command" else spec["commands"][0]
                    if quarantined:
                        command["allowed_paths"] = ["EXAMPLE_OTHER.txt"]
                    else:
                        command["argv"][-1] = "7"
                    self.source.write_text(json.dumps(spec), encoding="utf-8")
                    process = self._run(kind, self.output)
                    self.assertEqual(process.returncode, 3 if quarantined else 1, process.stderr)
                    result = self._report(process, self.output)
                    self.assertEqual(self.marker.read_text(encoding="utf-8"), "EXAMPLE_FIRST\n")
                    status = "quarantined" if quarantined else "failed"
                    self.assertEqual(
                        result["execution_status"] if kind == "command" else result["status"], status
                    )
                    if kind == "sequence":
                        self.assertEqual(result["completed_count"], 0)
                        self.assertEqual(len(result["command_results"]), 1)
                        self.assertEqual(json.loads(self.state.read_text(encoding="utf-8")), result)

    def test_missing_output_parent_keeps_existing_output_failure(self):
        self.source.write_text("{", encoding="utf-8")
        output = self.root / "EXAMPLE_MISSING" / "EXAMPLE_RESULT.json"
        for kind in ("command", "sequence"):
            with self.subTest(kind=kind):
                process = self._run(kind, output)
                self.assertEqual(process.stdout, "")
                self.assertFalse(output.parent.exists())
                self.assertFalse(self.marker.exists())
                if kind == "command":
                    self.assertEqual(process.returncode, 1)
                    self.assertIn("FileNotFoundError", process.stderr)
                else:
                    self.assertEqual(process.returncode, 2)
                    self.assertEqual(process.stderr, "")
                    result = json.loads(self.state.read_text(encoding="utf-8"))
                    self._refusal(kind, result)


if __name__ == "__main__":
    unittest.main()
