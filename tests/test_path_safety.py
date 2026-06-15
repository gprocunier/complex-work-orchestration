from __future__ import annotations

import tempfile
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.packets import file_snippet  # noqa: E402


class PathSafetyTests(unittest.TestCase):
    def test_allowed_file_cannot_escape_repo_root(self) -> None:
        with tempfile.NamedTemporaryFile() as handle:
            with self.assertRaises(SystemExit):
                file_snippet(Path(handle.name), max_lines=5)

    def test_internal_private_state_paths_are_rejected(self) -> None:
        for path in [ROOT / ".git" / "HEAD", ROOT / ".beads" / "README.md"]:
            with self.subTest(path=path):
                with self.assertRaises(SystemExit):
                    file_snippet(path, max_lines=5)

    def test_obvious_secret_files_are_rejected(self) -> None:
        secret = ROOT / "packet-test.key"
        try:
            secret.write_text("not a real key", encoding="utf-8")
            with self.assertRaises(SystemExit):
                file_snippet(secret, max_lines=5)
        finally:
            secret.unlink(missing_ok=True)

    def test_snippet_is_line_limited_and_redacted(self) -> None:
        snippet = file_snippet(ROOT / "policy" / "share-boundaries.yaml", max_lines=3)
        self.assertLessEqual(snippet["line_count"], 3)
        self.assertTrue(snippet["truncated"])
        self.assertNotIn("token=", snippet["content"].lower())


if __name__ == "__main__":
    unittest.main()
