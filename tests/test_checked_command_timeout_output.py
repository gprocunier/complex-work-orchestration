from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from cwo_core.checked_command import execute_checked_command, normalize_command_spec


def command_spec(cwd: str, source: str, **updates):
    value = {
        "spec_type": "cwo-checked-command-spec", "version": 1,
        "command_id": "EXAMPLE-timeout-output", "mode": "python-source",
        "argv": [], "cwd": cwd, "env": {}, "inherit_environment": False,
        "stdin": None, "source": source, "preflights": [],
        "mutation_intent": "none", "allowed_paths": [], "timeout_seconds": 1,
    }
    value.update(updates)
    return value


class CheckedCommandTimeoutOutputTest(unittest.TestCase):
    def assert_timeout_receipt(self, result, specification):
        normalized = normalize_command_spec(specification)
        canonical = json.dumps(
            normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8")
        source_hash = hashlib.sha256(normalized["source"].encode("utf-8")).hexdigest()
        self.assertEqual(result["result_type"], "cwo-checked-command-result")
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["command_id"], normalized["command_id"])
        self.assertEqual(result["mode"], "python-source")
        self.assertEqual(result["spec_sha256"], hashlib.sha256(canonical).hexdigest())
        self.assertEqual(result["preflight_status"], "passed")
        self.assertEqual(result["linter"], "py_compile")
        self.assertEqual(result["execution_status"], "failed")
        self.assertEqual(result["failure_class"], "execution-timeout")
        self.assertIs(result["execution_started"], True)
        self.assertIsNone(result["exit_code"])
        self.assertEqual(result["linted_sha256"], source_hash)
        self.assertEqual(result["executed_sha256"], source_hash)
        self.assertIs(result["hash_match"], True)
        self.assertIs(result["mutation_started"], False)
        self.assertEqual(result["mutated_paths"], [])
        self.assertIs(result["quarantine_required"], False)
        self.assertIs(result["quoting_error_prevented"], False)
        self.assertEqual(result["avoided_retry_cycles"], 0)
        for stream in ("stdout", "stderr"):
            self.assertIsInstance(result["diagnostics"][stream], str)
            self.assertLessEqual(len(result["diagnostics"][stream]), 4096)
        self.assertEqual(json.loads(json.dumps(result)), result)
        json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def timeout_variant(self, stdout, stderr):
        source = "print('EXAMPLE timeout adapter control', flush=True)\n"
        with tempfile.TemporaryDirectory() as root:
            specification = command_spec(root, source)

            def expire(argv, **kwargs):
                raise subprocess.TimeoutExpired(
                    argv, kwargs["timeout"], output=stdout, stderr=stderr,
                )

            with mock.patch("cwo_core.checked_command.subprocess.run", side_effect=expire) as run:
                result = execute_checked_command(specification)
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0][0], sys.executable)
            self.assertEqual(Path(run.call_args.args[0][1]).name, "command.py")
            self.assertEqual(len(run.call_args.args[0]), 2)
            self.assertEqual(run.call_args.kwargs, {
                "cwd": Path(root), "env": {}, "input": None, "text": True,
                "capture_output": True, "timeout": 1, "shell": False,
            })
            self.assert_timeout_receipt(result, specification)
        return result

    def test_real_timeout_retains_flushed_unicode_text(self):
        source = (
            "import sys\n"
            "import time\n"
            "sys.stdout.reconfigure(encoding='utf-8')\n"
            "sys.stderr.reconfigure(encoding='utf-8')\n"
            "print('EXAMPLE timeout stdout: caf\\u00e9 \\u96ea', flush=True)\n"
            "print('EXAMPLE timeout stderr: \\u03bb', file=sys.stderr, flush=True)\n"
            "time.sleep(3)\n"
        )
        with tempfile.TemporaryDirectory() as root:
            specification = command_spec(root, source)
            result = execute_checked_command(specification)
            self.assert_timeout_receipt(result, specification)
        self.assertEqual(result["diagnostics"]["stdout"], "EXAMPLE timeout stdout: caf\u00e9 \u96ea\n")
        self.assertEqual(result["diagnostics"]["stderr"], "EXAMPLE timeout stderr: \u03bb\n")

    def test_real_timeout_redacts_and_bounds_invalid_utf8_text(self):
        source = (
            "import os\n"
            "import sys\n"
            "import time\n"
            "out = os.environ['EXAMPLE_FAKE_STDOUT'].encode('utf-8')\n"
            "err = os.environ['EXAMPLE_FAKE_STDERR'].encode('utf-8')\n"
            "sys.stdout.buffer.write(b'EXAMPLE stdout: ' + out + b' ' + "
            "bytes([255, 254]) + b' ' + b'x' * 5000)\n"
            "sys.stdout.buffer.flush()\n"
            "sys.stderr.buffer.write(b'EXAMPLE stderr: ' + err + b' ' + "
            "bytes([226, 130]) + b' ' + b'y' * 5000)\n"
            "sys.stderr.buffer.flush()\n"
            "time.sleep(3)\n"
        )
        environment = {
            "EXAMPLE_FAKE_STDOUT": "EXAMPLE_FAKE_STDOUT_VALUE",
            "EXAMPLE_FAKE_STDERR": "EXAMPLE_FAKE_STDERR_VALUE",
            "EXAMPLE_EMPTY": "",
        }
        with tempfile.TemporaryDirectory() as root:
            specification = command_spec(root, source, env=environment)
            result = execute_checked_command(specification)
            self.assert_timeout_receipt(result, specification)
        expected_stdout = ("EXAMPLE stdout: [REDACTED] \\xff\\xfe " + "x" * 5000)[:4096]
        expected_stderr = ("EXAMPLE stderr: [REDACTED] \\xe2\\x82 " + "y" * 5000)[:4096]
        self.assertEqual(result["diagnostics"]["stdout"], expected_stdout)
        self.assertEqual(result["diagnostics"]["stderr"], expected_stderr)
        self.assertEqual(len(result["diagnostics"]["stdout"]), 4096)
        self.assertEqual(len(result["diagnostics"]["stderr"]), 4096)
        self.assertNotIn(environment["EXAMPLE_FAKE_STDOUT"], result["diagnostics"]["stdout"])
        self.assertNotIn(environment["EXAMPLE_FAKE_STDERR"], result["diagnostics"]["stderr"])

    def test_timeout_variant_retains_absent_output(self):
        result = self.timeout_variant(None, None)
        self.assertEqual(result["diagnostics"], {"stdout": "", "stderr": ""})

    def test_timeout_variant_retains_partial_text_stdout(self):
        stdout = "EXAMPLE partial stdout: caf\u00e9"
        result = self.timeout_variant(stdout, None)
        self.assertEqual(result["diagnostics"], {"stdout": stdout, "stderr": ""})

    def test_timeout_variant_retains_partial_text_stderr(self):
        stderr = "EXAMPLE partial stderr: \u03bb"
        result = self.timeout_variant(None, stderr)
        self.assertEqual(result["diagnostics"], {"stdout": "", "stderr": stderr})

    def test_timeout_variant_retains_empty_text_and_bytes(self):
        result = self.timeout_variant("", b"")
        self.assertEqual(result["diagnostics"], {"stdout": "", "stderr": ""})

    def test_python_source_success_remains_a_positive_control(self):
        source = (
            "import sys\n"
            "print('EXAMPLE success stdout', flush=True)\n"
            "print('EXAMPLE success stderr', file=sys.stderr, flush=True)\n"
        )
        with tempfile.TemporaryDirectory() as root:
            result = execute_checked_command(command_spec(root, source))
        self.assertEqual(result["preflight_status"], "passed")
        self.assertIs(result["execution_started"], True)
        self.assertEqual(result["execution_status"], "passed")
        self.assertEqual(result["exit_code"], 0)
        self.assertIsNone(result["failure_class"])
        self.assertIs(result["hash_match"], True)
        self.assertEqual(result["diagnostics"], {
            "stdout": "EXAMPLE success stdout\n",
            "stderr": "EXAMPLE success stderr\n",
        })


if __name__ == "__main__":
    unittest.main()
