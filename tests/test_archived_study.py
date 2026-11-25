"""Exercise the archive compatibility CLI on current source."""

import contextlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import comparative_evaluation as study


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = Path("evaluation/history/three-arm")


class ArchivedStudyTests(unittest.TestCase):
    def copy_archive(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return shutil.copytree(ROOT / ARCHIVE, Path(temporary.name) / ARCHIVE,
                               ignore=shutil.ignore_patterns("__pycache__"))

    def test_default_validate_accepts_a_source_snapshot_without_git(self):
        archive = self.copy_archive()
        snapshot = archive.parents[2]
        script = snapshot / "scripts/comparative_evaluation.py"
        script.parent.mkdir()
        shutil.copy2(study.__file__, script)
        cache = archive / "hidden/probes/__pycache__"
        cache.mkdir()
        (cache / "probe.cpython-312.pyc").write_bytes(b"generated cache")

        result = subprocess.run([sys.executable, "-B", script, "validate"], cwd=snapshot.parent,
                                capture_output=True, text=True, check=False, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {
            "valid": True,
            "protocol_id": "cwo-three-arm-comparative-evaluation",
            "digest": "043035355b54bbc12f7d769f1d662b6c60cd37132334b762a506cf8e29baadfa",
            "build_freeze_complete": False,
            "unbound_builds": ["codex_harness", "observer_harness"],
        })

    def test_validate_checks_roster_paths_and_bytes(self):
        archive = self.copy_archive()
        template = archive / "analysis-template.json"
        renamed = template.with_name("unexpected.json")
        original = template.read_bytes()
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(study.main(["--root", str(archive), "validate"]), 0)
            renamed.write_bytes(original)
            self.assertEqual(study.main(["--root", str(archive), "validate"]), 1)
            template.unlink()
            self.assertEqual(study.main(["--root", str(archive), "validate"]), 1)
            renamed.unlink()
            self.assertEqual(study.main(["--root", str(archive), "validate"]), 1)
            template.write_bytes(original + b"\n")
            self.assertEqual(study.main(["--root", str(archive), "validate"]), 1)
        self.assertIn('"valid": false', out.getvalue())

    def test_validate_refuses_replaced_build_freeze_and_links(self):
        archive = self.copy_archive()
        freeze = archive / "build-freeze.json"
        original = freeze.read_bytes()
        bound = json.loads(original)
        bound["codex_harness"] = {"form": "executable", "reference": "fixture", "sha256": "a" * 64}
        freeze.write_text(json.dumps(bound), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "contents differ"):
            study.validate_archive(archive)
        freeze.unlink()
        target = archive.parent / freeze.name
        target.write_bytes(original)
        freeze.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "nonregular file"):
            study.validate_archive(archive)

    def test_run_refuses_with_no_archive_access(self):
        with patch.object(study, "validate_archive", side_effect=AssertionError("archive read")):
            with contextlib.redirect_stderr(io.StringIO()) as err:
                result = study.main(["--root", "absent", "run", "--arm", "baseline", "--authorization", "granted",
                                     "--extra", "ignored"])
        self.assertEqual(result, 3)
        self.assertIn("running a study arm is a held external effect", err.getvalue())

    def test_run_help_and_malformed_or_retired_commands_end_in_parser(self):
        for args, code in ((["run", "--help"], 0), (["run", "--arm"], 2), (["score"], 2)):
            with self.subTest(args=args), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as exit_error:
                    study.main(args)
            self.assertEqual(exit_error.exception.code, code)
