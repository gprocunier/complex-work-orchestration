from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from cwo_core.checked_command import classify_command_complexity, execute_checked_command


def spec(cwd: str, **updates):
    value = {"spec_type": "cwo-checked-command-spec", "version": 1, "command_id": "cmd-1", "mode": "argv", "argv": [sys.executable, "--version"], "cwd": cwd, "env": {}, "inherit_environment": True, "stdin": None, "source": None, "preflights": [], "mutation_intent": "none", "allowed_paths": [], "timeout_seconds": 10}
    value.update(updates)
    return value


class CheckedCommandTest(unittest.TestCase):
    def test_argv_success_uses_shell_false_path(self):
        with tempfile.TemporaryDirectory() as root:
            result = execute_checked_command(spec(root))
        self.assertEqual(result["execution_status"], "passed")
        self.assertTrue(result["hash_match"])

    def test_raw_python_c_requires_typed_source(self):
        with tempfile.TemporaryDirectory() as root:
            result = execute_checked_command(spec(root, argv=[sys.executable, "-c", "print(1)"]))
        self.assertEqual(result["failure_class"], "typed-source-required")
        self.assertFalse(result["execution_started"])

    def test_shell_syntax_failure_is_clean_construction_failure(self):
        with tempfile.TemporaryDirectory() as root:
            result = execute_checked_command(spec(root, mode="shell-source", argv=[], source="if then\n"))
        self.assertEqual(result["failure_class"], "command-construction-failed")
        self.assertFalse(result["execution_started"])
        self.assertFalse(result["mutation_started"])
        self.assertFalse(result["quarantine_required"])

    def test_shell_exact_hash_and_output(self):
        with tempfile.TemporaryDirectory() as root:
            result = execute_checked_command(spec(root, mode="shell-source", argv=[], source="printf checked"))
        self.assertEqual(result["diagnostics"]["stdout"], "checked")
        self.assertEqual(result["linted_sha256"], result["executed_sha256"])

    def test_python_compile_failure_prevents_execution(self):
        with tempfile.TemporaryDirectory() as root:
            result = execute_checked_command(spec(root, mode="python-source", argv=[], source="def bad(:\n"))
        self.assertEqual(result["preflight_status"], "failed")
        self.assertFalse(result["execution_started"])

    def test_nested_json_and_regex_preflight(self):
        with tempfile.TemporaryDirectory() as root:
            result = execute_checked_command(spec(root, preflights=[{"kind": "json", "value": "{"}, {"kind": "regex", "value": "["}]))
        self.assertEqual(result["failure_class"], "command-construction-failed")
        self.assertEqual(result["avoided_retry_cycles"], 1)

    def test_scoped_mutation_is_attributed(self):
        with tempfile.TemporaryDirectory() as root:
            result = execute_checked_command(spec(root, mode="python-source", argv=[], source="from pathlib import Path\nPath('allowed.txt').write_text('ok')\n", mutation_intent="workspace-scoped", allowed_paths=["allowed.txt"]))
        self.assertEqual(result["execution_status"], "passed")
        self.assertEqual(result["mutated_paths"], ["allowed.txt"])

    def test_out_of_scope_mutation_quarantines(self):
        with tempfile.TemporaryDirectory() as root:
            result = execute_checked_command(spec(root, mode="python-source", argv=[], source="from pathlib import Path\nPath('outside.txt').write_text('x')\n", mutation_intent="workspace-scoped", allowed_paths=["allowed.txt"]))
        self.assertEqual(result["failure_class"], "scope-violation")
        self.assertTrue(result["quarantine_required"])

    def test_diagnostics_redact_explicit_environment_values(self):
        with tempfile.TemporaryDirectory() as root:
            result = execute_checked_command(spec(root, mode="python-source", argv=[], source="import os\nprint(os.environ['SECRET'])\n", env={"SECRET": "top-secret"}, inherit_environment=False))
        self.assertIn("[REDACTED]", result["diagnostics"]["stdout"])
        self.assertNotIn("top-secret", result["diagnostics"]["stdout"])

    def test_complexity_classification(self):
        with tempfile.TemporaryDirectory() as root:
            result = classify_command_complexity(spec(root, mode="shell-source", argv=[], source="echo ok", mutation_intent="workspace-scoped", allowed_paths=["x"]))
        self.assertTrue(result["checked_execution_required"])
        self.assertIn("typed-source", result["reasons"])

    def test_schema_files_are_json(self):
        for name in ("checked-command-spec.schema.json", "checked-command-result.schema.json"):
            self.assertIsInstance(json.loads((ROOT / "schemas" / name).read_text()), dict)


if __name__ == "__main__":
    unittest.main()
