from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from check_installed_skill import (  # noqa: E402
    INSTALL_MANIFEST_NAME,
    build_manifest,
    installed_status,
    write_install_manifest,
)
from cwo_core import util as cwo_util  # noqa: E402


class CheckInstalledSkillTests(unittest.TestCase):
    def make_skill_tree(self, root: Path) -> None:
        (root / "scripts").mkdir(parents=True)
        (root / "docs").mkdir()
        (root / "SKILL.md").write_text("# Skill\n", encoding="utf-8")
        (root / "README.md").write_text("# Readme\n", encoding="utf-8")
        (root / "VERSION").write_text("1.2.3\n", encoding="utf-8")
        (root / "scripts" / "helper.py").write_text("print('ok')\n", encoding="utf-8")
        (root / "docs" / "index.html").write_text("<!doctype html><title>Docs</title>\n", encoding="utf-8")
        prompts = root / "prompts" / "archive"
        prompts.mkdir(parents=True)
        (root / "prompts" / "cwo-sol-operator-e.md").write_text("Candidate E\n", encoding="utf-8")
        (prompts / "cwo-sol-operator-e-v5-qualified.md").write_text("Qualified v5\n", encoding="utf-8")
        calibration = root / "calibration"
        calibration.mkdir()
        (calibration / "skl-return-language-contract-v1.json").write_text("{\"artifact_type\": \"skl-corpus-contract\"}\n", encoding="utf-8")
        (calibration / "skl-return-language-corpus-v1.json").write_text("{\"artifact_type\": \"skl-return-language-corpus\"}\n", encoding="utf-8")
        (calibration / "skl-return-language-tuning-v1.json").write_text("{\"artifact_type\": \"skl-return-language-tuning-v1\"}\n", encoding="utf-8")
        (calibration / "skl-return-language-calibration-report-latest.json").write_text("{\"artifact_type\": \"skl-return-language-calibration-report\"}\n", encoding="utf-8")

    def test_status_is_current_for_matching_install_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "source"
            installed = Path(tmpdir) / "skills" / "complex-work-orchestration"
            source.mkdir()
            self.make_skill_tree(source)
            shutil.copytree(source, installed)

            status = installed_status(source, installed)

        self.assertEqual(status["status"], "current")
        self.assertEqual(status["source_version"], "1.2.3")
        self.assertEqual(status["installed_version"], "1.2.3")
        self.assertEqual(status["missing_files"], [])
        self.assertEqual(status["changed_files"], [])
        self.assertEqual(status["extra_files"], [])
        self.assertIn("source", status["calibration_artifacts"])
        calibration = status["calibration_artifacts"]
        self.assertIsNotNone(calibration["source"]["contract"])
        self.assertIsNotNone(calibration["source"]["corpus"])
        self.assertIsNotNone(calibration["source"]["tuning"])
        self.assertIsNotNone(calibration["source"]["latest_report"])


    def test_status_reports_changed_and_extra_installed_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "source"
            installed = Path(tmpdir) / "skills" / "complex-work-orchestration"
            source.mkdir()
            self.make_skill_tree(source)
            shutil.copytree(source, installed)
            (installed / "SKILL.md").write_text("# Drifted\n", encoding="utf-8")
            (installed / "docs" / "extra.html").write_text("<p>extra</p>\n", encoding="utf-8")

            status = installed_status(source, installed)

            self.assertIn("source", status["calibration_artifacts"])
            self.assertIsNotNone(status["calibration_artifacts"]["source"]["contract"])
            self.assertEqual(
                status["calibration_artifacts"]["source"]["contract"],
                status["calibration_artifacts"]["installed"]["contract"],
            )

            self.assertEqual(status["status"], "drift")
            self.assertIn("SKILL.md", status["changed_files"])
            self.assertIn("docs/extra.html", status["extra_files"])

    def test_status_reports_archived_prompt_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "source"
            installed = Path(tmpdir) / "skills" / "complex-work-orchestration"
            source.mkdir()
            self.make_skill_tree(source)
            shutil.copytree(source, installed)
            archived = installed / "prompts" / "archive" / "cwo-sol-operator-e-v5-qualified.md"
            archived.write_text("drifted\n", encoding="utf-8")

            status = installed_status(source, installed)

        self.assertEqual(status["status"], "drift")
        self.assertIn("prompts/archive/cwo-sol-operator-e-v5-qualified.md", status["changed_files"])

    def test_generated_manifest_and_python_caches_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "source"
            root.mkdir()
            self.make_skill_tree(root)
            (root / INSTALL_MANIFEST_NAME).write_text("{}\n", encoding="utf-8")
            (root / "scripts" / "__pycache__").mkdir()
            (root / "scripts" / "__pycache__" / "helper.cpython-314.pyc").write_bytes(b"cache")

            manifest = build_manifest(root)

        paths = {item["path"] for item in manifest["files"]}
        self.assertNotIn(INSTALL_MANIFEST_NAME, paths)
        self.assertFalse(any("__pycache__" in path for path in paths))

    def test_write_install_manifest_does_not_change_content_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "source"
            installed = Path(tmpdir) / "skills" / "complex-work-orchestration"
            source.mkdir()
            self.make_skill_tree(source)
            shutil.copytree(source, installed)
            before = installed_status(source, installed)

            write_install_manifest(installed, before)
            after = installed_status(source, installed)

        self.assertEqual(before["status"], "current")
        self.assertEqual(after["status"], "current")
        self.assertEqual(before["installed_content_sha256"], after["installed_content_sha256"])

    def test_atomic_write_preserves_existing_file_when_replace_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "manifest.json"
            target.write_text("old\n", encoding="utf-8")
            with patch("cwo_core.util.os.replace", side_effect=OSError("boom")):
                with self.assertRaises(OSError):
                    cwo_util.atomic_write_text(target, "new\n")
            self.assertEqual(target.read_text(encoding="utf-8"), "old\n")
            self.assertEqual(list(Path(tmpdir).glob(".manifest.json.*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
