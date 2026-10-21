from __future__ import annotations
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("check_documentation_cli", ROOT / "scripts/check_documentation.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

class DocumentationCLITests(unittest.TestCase):
    def invoke(self, errors, args):
        output = io.StringIO()
        with patch.object(MODULE, "check", return_value=errors), contextlib.redirect_stdout(output):
            status = MODULE.main(args)
        if "--json" in args:
            report = json.loads(output.getvalue())
            self.assertIs(type(report["ok"]), bool)
            self.assertIs(type(report["version"]), int)
        return status, output.getvalue()

    def test_human_success_is_compatible(self):
        status, text = self.invoke([], [])
        self.assertEqual(status, 0)
        self.assertEqual(text, "Maintained Markdown links and legacy Pages routes passed.\n")

    def test_human_failure_is_compatible(self):
        status, text = self.invoke(["missing one", "missing two"], [])
        self.assertEqual(status, 1)
        self.assertEqual(text, "ERROR: missing one\nERROR: missing two\n")

    def test_json_success_has_one_versioned_document(self):
        status, text = self.invoke([], ["--json"])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(text), {"version": 1, "ok": True, "errors": []})

    def test_json_errors_preserve_order_and_unicode(self):
        errors = ["missing café.md", 'bad \"quote\"', "line\nnext"]
        status, text = self.invoke(errors, ["--json"])
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(text), {"version": 1, "ok": False, "errors": errors})
        self.assertEqual(len(text.splitlines()), 1)

    def test_api_still_returns_a_list(self):
        self.assertIsInstance(MODULE.check(), list)

    def test_actual_cli_success(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/check_documentation.py"), "--json"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"version": 1, "ok": True, "errors": []})
        self.assertEqual(result.stderr, "")

    def test_actual_cli_failed_link_report_and_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            (root / "tests/fixtures").mkdir(parents=True)
            shutil.copy2(ROOT / "scripts/check_documentation.py", root / "scripts/check_documentation.py")
            (root / "tests/fixtures/site-legacy-routes.json").write_text("{}")
            (root / "README.md").write_text("[Missing](missing.md)")
            (root / "CONTRIBUTING.md").write_text("")
            env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
            result = subprocess.run([sys.executable, str(root / "scripts/check_documentation.py"), "--json"], cwd=root, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout), {"version": 1, "ok": False, "errors": ["README.md: missing/outside target missing.md"]})
            self.assertEqual(result.stderr, "")

    def test_actual_cli_unicode_error_with_ascii_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            (root / "tests/fixtures").mkdir(parents=True)
            shutil.copy2(ROOT / "scripts/check_documentation.py", root / "scripts/check_documentation.py")
            (root / "tests/fixtures/site-legacy-routes.json").write_text("{}")
            (root / "README.md").write_text("[Missing](café.md)", encoding="utf-8")
            (root / "CONTRIBUTING.md").write_text("")
            env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "ascii", "PYTHONDONTWRITEBYTECODE": "1"}
            result = subprocess.run([sys.executable, str(root / "scripts/check_documentation.py"), "--json"], cwd=root, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr, "")
            report = json.loads(result.stdout)
            self.assertEqual(report["errors"], ["README.md: missing/outside target café.md"])
            self.assertIs(type(report["ok"]), bool)
            self.assertIs(report["ok"], False)

    def test_actual_human_success_and_failure(self):
        for missing in (False, True):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "scripts").mkdir()
                (root / "tests/fixtures").mkdir(parents=True)
                shutil.copy2(ROOT / "scripts/check_documentation.py", root / "scripts/check_documentation.py")
                (root / "tests/fixtures/site-legacy-routes.json").write_text("{}")
                (root / "README.md").write_text("[Missing](missing.md)" if missing else "")
                (root / "CONTRIBUTING.md").write_text("")
                result = subprocess.run([sys.executable, str(root / "scripts/check_documentation.py")], cwd=root, capture_output=True, text=True)
                self.assertEqual(result.returncode, int(missing))
                self.assertEqual(result.stderr, "")
                self.assertEqual(result.stdout, "ERROR: README.md: missing/outside target missing.md\n" if missing else "Maintained Markdown links and legacy Pages routes passed.\n")

    def test_abbreviated_option_is_not_json_opt_in(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/check_documentation.py"), "--j"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")

    def test_actual_cli_unknown_option_is_usage_error(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/check_documentation.py"), "--unknown-option"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("unrecognized arguments", result.stderr)

if __name__ == "__main__":
    unittest.main()
