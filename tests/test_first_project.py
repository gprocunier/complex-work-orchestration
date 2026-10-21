from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("create_first_project", ROOT / "scripts/create_first_project.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FirstProjectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.destination = Path(self.tmp.name) / "project with spaces"
        module.create(self.destination)

    def run_python(self, *args):
        return subprocess.run([sys.executable, *args], cwd=self.destination,
                              text=True, capture_output=True, timeout=20)

    def test_starter_fails_and_reference_satisfies_contract(self):
        result = self.run_python("-m", "unittest", "-v")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAILED", result.stderr)
        shutil.copyfile(ROOT / "examples/first-project/reference/checker.py", self.destination / "checker.py")
        result = self.run_python("-m", "unittest", "-v")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for args, expected in [(["service.json"], 0), (["invalid.json"], 1),
                               (["absent.json"], 2), ([], 2), (["a", "b"], 2)]:
            with self.subTest(args=args):
                result = self.run_python("checker.py", *args)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        for content, expected in [("{", 2), ("[]", 1), ('{"host":"x","port":65535}', 0)]:
            (self.destination / "input.json").write_text(content)
            self.assertEqual(self.run_python("checker.py", "input.json").returncode, expected)
        (self.destination / "input.json").write_bytes(b"\xff")
        self.assertEqual(self.run_python("checker.py", "input.json").returncode, 2)

    def test_creation_refuses_existing_directory(self):
        marker = self.destination / "do-not-change"
        marker.write_text("preserved")
        with self.assertRaisesRegex(ValueError, "already exists"):
            module.create(self.destination)
        self.assertEqual(marker.read_text(), "preserved")

    def test_creation_refuses_dangling_symlink(self):
        target = Path(self.tmp.name) / "dangling"
        target.symlink_to(Path(self.tmp.name) / "missing")
        with self.assertRaises(ValueError):
            module.create(target)


if __name__ == "__main__":
    unittest.main()
