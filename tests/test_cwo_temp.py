from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_temp import cleanup_cwo_temp, parse_duration_seconds  # noqa: E402


class CwoTempTests(unittest.TestCase):
    def test_duration_parser_accepts_units(self) -> None:
        self.assertEqual(parse_duration_seconds("48h"), 172800)
        self.assertEqual(parse_duration_seconds("2d"), 172800)
        self.assertEqual(parse_duration_seconds("15m"), 900)
        self.assertEqual(parse_duration_seconds("30"), 30)

    def test_cleanup_defaults_to_dry_run_and_preserves_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            old_session = Path(tmpdir) / "cwo-user-old"
            old_session.mkdir()
            stale_file = old_session / "artifact.txt"
            stale_file.write_text("stale\n", encoding="utf-8")
            old_time = time.time() - 3600
            os.utime(old_session, (old_time, old_time))
            with patch.dict(
                os.environ,
                {"CWO_TEMP_ROOT": tmpdir, "CWO_SESSION_ID": "current", "USER": "user"},
                clear=False,
            ):
                result = cleanup_cwo_temp(scope="session", older_than_seconds=60, force=False, now=time.time())
            self.assertEqual(result["summary"], {"would_delete": 1})
            self.assertTrue(stale_file.exists())

    def test_cleanup_force_deletes_only_cwo_session_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            stale_session = Path(tmpdir) / "cwo-user-stale"
            stale_session.mkdir()
            (stale_session / "artifact.txt").write_text("stale\n", encoding="utf-8")
            non_cwo = Path(tmpdir) / "other-tool"
            non_cwo.mkdir()
            old_time = time.time() - 3600
            os.utime(stale_session, (old_time, old_time))
            os.utime(non_cwo, (old_time, old_time))
            with patch.dict(
                os.environ,
                {"CWO_TEMP_ROOT": tmpdir, "CWO_SESSION_ID": "current", "USER": "user"},
                clear=False,
            ):
                result = cleanup_cwo_temp(scope="session", older_than_seconds=60, force=True, now=time.time())
            self.assertEqual(result["summary"], {"delete": 1})
            self.assertFalse(stale_session.exists())
            self.assertTrue(non_cwo.exists())

    def test_cleanup_session_scope_ignores_other_users(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            mine = Path(tmpdir) / "cwo-user-stale"
            mine.mkdir()
            other = Path(tmpdir) / "cwo-other-stale"
            other.mkdir()
            old_time = time.time() - 3600
            os.utime(mine, (old_time, old_time))
            os.utime(other, (old_time, old_time))
            with patch.dict(
                os.environ,
                {"CWO_TEMP_ROOT": tmpdir, "CWO_SESSION_ID": "current", "USER": "user"},
                clear=False,
            ):
                result = cleanup_cwo_temp(scope="session", older_than_seconds=60, force=True, now=time.time())
            self.assertEqual(result["summary"], {"delete": 1})
            self.assertFalse(mine.exists())
            self.assertTrue(other.exists())

    def test_cleanup_protects_current_session_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            current = Path(tmpdir) / "cwo-test-current"
            current.mkdir()
            old_time = time.time() - 3600
            os.utime(current, (old_time, old_time))
            with patch.dict(
                os.environ,
                {"CWO_TEMP_ROOT": tmpdir, "CWO_SESSION_ID": "current", "USER": "test"},
                clear=False,
            ):
                result = cleanup_cwo_temp(scope="session", older_than_seconds=60, force=True, now=time.time())
            self.assertEqual(result["summary"], {"protect_current_session": 1})
            self.assertTrue(current.exists())

    def test_cleanup_exchange_operates_on_exchange_contents(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            exchange = Path(tmpdir) / "cwo-exchange"
            exchange.mkdir()
            old_file = exchange / "cwo-old-return.md"
            old_file.write_text("old\n", encoding="utf-8")
            unrelated = exchange / "unrelated-tool-output.txt"
            unrelated.write_text("keep\n", encoding="utf-8")
            old_time = time.time() - 3600
            os.utime(old_file, (old_time, old_time))
            os.utime(unrelated, (old_time, old_time))
            with patch.dict(os.environ, {"CWO_TEMP_ROOT": tmpdir, "CWO_SESSION_ID": "current"}, clear=False):
                result = cleanup_cwo_temp(scope="exchange", older_than_seconds=60, force=True, now=time.time())
            self.assertEqual(result["summary"], {"delete": 1})
            self.assertTrue(exchange.exists())
            self.assertFalse(old_file.exists())
            self.assertTrue(unrelated.exists())

    def test_cwo_py_dispatches_temp_help(self) -> None:
        result = subprocess.run(
            [sys.executable, "scripts/cwo.py", "temp", "--help"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("cleanup", result.stdout)


if __name__ == "__main__":
    unittest.main()
