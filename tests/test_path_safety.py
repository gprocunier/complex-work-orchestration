from __future__ import annotations

import tempfile
import sys
import unittest
from unittest.mock import patch
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.packets import file_snippet  # noqa: E402
from cwo_core.paths import assert_safe_output_path, cwo_temp_dir, cwo_temp_path, is_cwo_temp_path  # noqa: E402


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

    def test_output_path_allows_repo_and_tmp_artifacts(self) -> None:
        self.assertEqual(assert_safe_output_path(ROOT / "review-output.json"), ROOT / "review-output.json")
        self.assertEqual(assert_safe_output_path(Path("review-output.json")), ROOT / "review-output.json")
        tmp_path = Path(tempfile.gettempdir()) / "cwo-output-test.json"
        self.assertEqual(assert_safe_output_path(tmp_path), tmp_path)

    def test_output_path_rejects_control_paths_and_secret_names(self) -> None:
        with self.assertRaises(SystemExit):
            assert_safe_output_path(ROOT / ".git" / "cwo-output.json")
        with self.assertRaises(SystemExit):
            assert_safe_output_path(Path(tempfile.gettempdir()) / "id_rsa")

    def test_output_path_rejects_symlink_target_and_symlink_parent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            target = tmp / "target.txt"
            target.write_text("x\n", encoding="utf-8")
            link = tmp / "link.txt"
            link.symlink_to(target)
            with self.assertRaises(SystemExit):
                assert_safe_output_path(link)

            real_parent = tmp / "real"
            real_parent.mkdir()
            parent_link = tmp / "parent-link"
            parent_link.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaises(SystemExit):
                assert_safe_output_path(parent_link / "out.txt")

    def test_cwo_temp_session_and_exchange_dirs_use_safe_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(
                "os.environ",
                {"CWO_TEMP_ROOT": tmpdir, "CWO_SESSION_ID": "session 1", "USER": "test user"},
                clear=False,
            ):
                session_dir = cwo_temp_dir(scope="session")
                exchange_dir = cwo_temp_dir(scope="exchange")
                self.assertEqual(session_dir.name, "cwo-test-user-session-1")
                self.assertEqual(exchange_dir.name, "cwo-exchange")
                self.assertEqual(session_dir.stat().st_mode & 0o777, 0o700)
                self.assertEqual(exchange_dir.stat().st_mode & 0o7777, 0o1770)
                artifact = cwo_temp_path("work graph.md", purpose="fallback graph")
                self.assertTrue(str(artifact).endswith("fallback-graph/work-graph.md"))
                self.assertTrue(is_cwo_temp_path(artifact))
                self.assertFalse(is_cwo_temp_path(Path(tmpdir) / "not-cwo" / "artifact.txt"))

    def test_cwo_temp_rejects_relative_or_symlinked_roots_and_parts(self) -> None:
        with patch.dict("os.environ", {"CWO_TEMP_ROOT": "relative-temp-root"}, clear=False):
            with self.assertRaises(SystemExit):
                cwo_temp_dir(scope="session")
        with tempfile.TemporaryDirectory() as tmpdir:
            real = Path(tmpdir) / "real"
            real.mkdir()
            link = Path(tmpdir) / "link"
            link.symlink_to(real, target_is_directory=True)
            with patch.dict("os.environ", {"CWO_TEMP_ROOT": str(link)}, clear=False):
                with self.assertRaises(SystemExit):
                    cwo_temp_dir(scope="session")
            broken = Path(tmpdir) / "broken"
            broken.symlink_to(Path(tmpdir) / "missing", target_is_directory=True)
            with patch.dict("os.environ", {"CWO_TEMP_ROOT": str(broken / "nested")}, clear=False):
                with self.assertRaises(SystemExit):
                    cwo_temp_dir(scope="session")

    def test_cwo_temp_rejects_private_dir_owned_by_another_user(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_dir = Path(tmpdir) / "cwo-test-session"
            session_dir.mkdir()
            with patch.dict(
                "os.environ",
                {"CWO_TEMP_ROOT": tmpdir, "CWO_SESSION_ID": "session", "USER": "test"},
                clear=False,
            ):
                with patch("cwo_core.paths.os.getuid", return_value=os.getuid() + 1):
                    with self.assertRaises(SystemExit):
                        cwo_temp_dir(scope="session")


if __name__ == "__main__":
    unittest.main()
