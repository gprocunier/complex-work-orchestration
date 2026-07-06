from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class GenerateSiteTests(unittest.TestCase):
    def test_generated_site_shell_is_current(self) -> None:
        result = subprocess.run(
            [sys.executable, "scripts/generate_site.py", "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
