"""Share a read-only consumer only across the same restored private image.

Installer transitions remain real body actions.  The outer TestCase still owns
preparation and cleanup, and the consumer still runs all its product oracles.
Replacement images have separate flows, including a new install-record timestamp.
"""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys

from tests import test_install_projection as fixture


CHECKER_BOOTSTRAP = (
    "import runpy,sys;sys.path.insert(0,sys.argv.pop(1));"
    "runpy.run_module('check_installed_skill',run_name='__main__')"
)


def checked_cleanups(case):
    if not case.doCleanups():
        raise AssertionError("EXAMPLE private installed row cleanup failed")


def prepare_replacement(case):
    """Arrange both private flows in the actual outer setup phase.

    Existing manually constructed isolation/timeout controls request an ordinary
    fixture. Families call this only while retaining their replacement scenario.
    """
    if getattr(case, "fixture_variant", "family") == "ordinary":
        return
    other = type(case)(case._testMethodName)
    other.fixture_variant = "ordinary"
    case.addCleanup(checked_cleanups, other)
    other.setUp()
    case.assertNotEqual(case.install.tmp, other.install.tmp)
    case.assertEqual(case.expected, other.expected)
    case.assertIsNot(case.expected, other.expected)
    case.assertFalse(case.source.samefile(other.source))
    case.assertFalse(case.install.target.samefile(other.install.target))
    case.assertFalse((case.install.target / "SECURITY.md").samefile(
        other.install.target / "SECURITY.md"))
    case.replacement_case = other


class RestoredInstalledRows:
    """Keep byte, mode, coordinate and source-absence proof for shared rows."""

    def __init__(self, case, capture_metadata=None):
        self.case = case
        self.capture_metadata = capture_metadata
        self.target = fixture.snapshot(case.install.target)
        self.root_mode = case.install.target.stat().st_mode
        info = case.install.target.stat()
        self.root_identity = (info.st_dev, info.st_ino)
        self.source = fixture.snapshot(case.source)
        self.security = (case.source / "SECURITY.md").read_bytes()
        self.inputs = fixture.snapshot(case.install.tmp / "inputs")
        self.rows = []

    def observe(self, row_id):
        case = self.case
        case.assert_image(case.install.target, case.expected)
        case.assertEqual(fixture.snapshot(case.install.target), self.target)
        case.assertEqual(case.install.target.stat().st_mode, self.root_mode)
        info = case.install.target.stat()
        case.assertEqual((info.st_dev, info.st_ino), self.root_identity)
        case.assertEqual(fixture.snapshot(case.install.tmp / "inputs"), self.inputs)
        metadata = {} if self.capture_metadata is None else copy.deepcopy(self.capture_metadata())
        held = case.install.tmp / "EXAMPLE_held_source"
        case.source.rename(held)
        try:
            self._check_without_source()
        finally:
            held.rename(case.source)
        self.rows.append({
            "row_id": row_id, "source_absent_checker": "record-consistent",
            "target_snapshot_sha256": self._digest(fixture.snapshot(case.install.target)),
            "root_mode": self.root_mode,
            "root_identity": self.root_identity,
            "metadata": metadata,
        })

    def _check_without_source(self):
        case = self.case
        case.assertFalse(case.source.exists())
        before = fixture.snapshot(case.install.tmp)
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", CHECKER_BOOTSTRAP,
             str(case.install.target / "scripts"), "--record-check",
             "--installed-dir", str(case.install.target), "--json"],
            cwd=case.install.tmp / "home", env=case.env,
            capture_output=True, text=True, check=False, timeout=60,
        )
        case.assertEqual(result.returncode, 0, result.stderr)
        case.assertEqual(json.loads(result.stdout)["status"], "record-consistent")
        case.assertEqual(fixture.snapshot(case.install.tmp), before)
        case.assertEqual(fixture.snapshot(case.install.target), self.target)

    def restore_source(self):
        case = self.case
        (case.source / "SECURITY.md").write_bytes(self.security)
        case.assertEqual(fixture.snapshot(case.source), self.source)
        if hasattr(case, "source_image"):
            case.source_image = fixture.snapshot(case.source)

    def exercise_rollbacks(self, modes=("activation", "term")):
        """Observe fresh and execute only this family's retained rollback modes."""
        case = self.case
        with case.subTest(row="fresh"):
            self.observe("fresh")
        for mode in modes:
            with case.subTest(row=mode + "-rollback"):
                case.rollback(mode)
                self.observe(mode + "-rollback")
                self.restore_source()

    def retain(self):
        # Original lifecycle metadata goes through each family's real retainer
        # after the shared product flow; this side output is equivalence only.
        fields = ("row_id", "source_absent_checker", "target_snapshot_sha256", "root_mode", "root_identity")
        observations = [{key: row[key] for key in fields} for row in self.rows]
        print("CWO_INSTALLED_SHARED_ROWS " + json.dumps(observations, sort_keys=True), flush=True)

    @staticmethod
    def _digest(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
