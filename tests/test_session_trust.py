from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_session import session_file_trust_report  # noqa: E402


@unittest.skipUnless(os.name == "posix", "trust checks are POSIX-only")
class SessionFileTrustTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _session(self, mode: int = 0o600) -> Path:
        path = self.root / "session.jsonl"
        path.write_text("{}\n", encoding="utf-8")
        path.chmod(mode)
        return path

    def test_private_regular_file_is_trusted(self) -> None:
        report = session_file_trust_report(self._session())
        self.assertTrue(report["trusted"], report["reasons"])
        self.assertTrue(report["checked"])

    def test_group_writable_file_is_untrusted(self) -> None:
        report = session_file_trust_report(self._session(0o660))
        self.assertFalse(report["trusted"])
        self.assertIn("group- or world-writable", "; ".join(report["reasons"]))

    def test_world_writable_file_is_untrusted(self) -> None:
        report = session_file_trust_report(self._session(0o646))
        self.assertFalse(report["trusted"])

    def test_symlink_is_untrusted(self) -> None:
        target = self._session()
        link = self.root / "link.jsonl"
        link.symlink_to(target)
        report = session_file_trust_report(link)
        self.assertFalse(report["trusted"])
        self.assertIn("symlink", "; ".join(report["reasons"]))

    def test_missing_file_is_untrusted(self) -> None:
        report = session_file_trust_report(self.root / "absent.jsonl")
        self.assertFalse(report["trusted"])

    def test_world_writable_directory_is_untrusted(self) -> None:
        session = self._session()
        self.root.chmod(0o777)
        self.addCleanup(self.root.chmod, 0o700)
        report = session_file_trust_report(session)
        self.assertFalse(report["trusted"])
        self.assertIn("world-writable", "; ".join(report["reasons"]))

    def test_sticky_world_writable_directory_is_trusted(self) -> None:
        session = self._session()
        self.root.chmod(0o1777)
        self.addCleanup(self.root.chmod, 0o700)
        report = session_file_trust_report(session)
        self.assertTrue(report["trusted"], report["reasons"])


if __name__ == "__main__":
    unittest.main()
