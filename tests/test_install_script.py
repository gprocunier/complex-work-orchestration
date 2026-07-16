from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class InstallScriptTests(unittest.TestCase):
    def run_installer(self, *args: str, os_release: Path | None = None) -> subprocess.CompletedProcess[str]:
        env = {**os.environ}
        if os_release is not None:
            env["OS_RELEASE_FILE"] = str(os_release)
        return subprocess.run(
            [str(ROOT / "scripts" / "install.sh"), *args],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_copr_guidance_does_not_expand_raw_env_into_copy_paste_command(self) -> None:
        text = (ROOT / "scripts" / "install.sh").read_text(encoding="utf-8")

        self.assertIn("valid_copr_ref()", text)
        self.assertIn("print_copr_command", text)
        self.assertIn('PUBLIC_BEADS_COPR="greg-at-redhat/beads"', text)
        self.assertIn('BEADS_COPR="${BEADS_COPR:-}"', text)
        self.assertNotIn("sudo dnf copr enable $BEADS_COPR", text)
        self.assertIn("sudo dnf copr enable '$copr_ref'", text)
        self.assertIn("brew install beads", text)
        self.assertIn("https://raw.githubusercontent.com/gastownhall/beads/main/scripts/install.sh", text)
        self.assertIn("https://gastownhall.github.io/beads/", text)
        self.assertIn("reduced-durability Markdown handoff state", text)

    def test_install_and_reinstall_preserves_previous_install_outside_skills_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            skills_dir = Path(tmpdir) / "skills"
            first = self.run_installer("--skills-dir", str(skills_dir), "--yes")
            self.assertEqual(first.returncode, 0, first.stderr or first.stdout)

            target = skills_dir / "complex-work-orchestration"
            marker = target / "LOCAL_MARKER"
            marker.write_text("previous install marker\n", encoding="utf-8")

            second = self.run_installer("--skills-dir", str(skills_dir), "--yes")
            self.assertEqual(second.returncode, 0, second.stderr or second.stdout)

            backups = sorted((Path(tmpdir) / "skill-backups").glob("complex-work-orchestration.prev.*"))
            self.assertTrue(target.is_dir())
            self.assertEqual(len(backups), 1)
            previous = backups[0]
            self.assertTrue(previous.is_dir())
            self.assertFalse((skills_dir / "complex-work-orchestration.prev").exists())
            self.assertFalse(marker.exists())
            self.assertEqual((previous / "LOCAL_MARKER").read_text(encoding="utf-8"), "previous install marker\n")
            self.assertIn("Previous install moved to backup", second.stdout)

    def test_uninstall_moves_active_install_outside_skills_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            skills_dir = Path(tmpdir) / "skills"
            install = self.run_installer("--skills-dir", str(skills_dir), "--yes")
            self.assertEqual(install.returncode, 0, install.stderr or install.stdout)

            target = skills_dir / "complex-work-orchestration"
            uninstall = self.run_installer("--skills-dir", str(skills_dir), "--yes", "--uninstall")
            self.assertEqual(uninstall.returncode, 0, uninstall.stderr or uninstall.stdout)

            backups = sorted((Path(tmpdir) / "skill-backups").glob("complex-work-orchestration.prev.*"))
            self.assertFalse(target.exists())
            self.assertEqual(len(backups), 1)
            previous = backups[0]
            self.assertTrue(previous.is_dir())
            self.assertFalse((skills_dir / "complex-work-orchestration.prev").exists())
            self.assertIn("Uninstalled skill; backup kept", uninstall.stdout)

    def test_install_dry_run_does_not_create_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            skills_dir = Path(tmpdir) / "skills"
            dry_run = self.run_installer("--skills-dir", str(skills_dir), "--yes", "--dry-run")
            self.assertEqual(dry_run.returncode, 0, dry_run.stderr or dry_run.stdout)

            self.assertFalse((skills_dir / "complex-work-orchestration").exists())
            self.assertIn("Would create staging install", dry_run.stdout)

    def test_installer_copies_calibration_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            skills_dir = Path(tmpdir) / "skills"
            install = self.run_installer("--skills-dir", str(skills_dir), "--yes")
            self.assertEqual(install.returncode, 0, install.stderr or install.stdout)

            target = skills_dir / "complex-work-orchestration" / "calibration"
            self.assertTrue(target.is_dir())
            for filename in [
                "skl-return-language-contract-v1.json",
                "skl-return-language-corpus-v1.json",
                "skl-return-language-tuning-v1.json",
                "skl-return-language-calibration-report-latest.json",
            ]:
                self.assertTrue((target / filename).is_file())

    def test_uninstall_dry_run_keeps_active_install(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            skills_dir = Path(tmpdir) / "skills"
            install = self.run_installer("--skills-dir", str(skills_dir), "--yes")
            self.assertEqual(install.returncode, 0, install.stderr or install.stdout)

            dry_run = self.run_installer("--skills-dir", str(skills_dir), "--yes", "--dry-run", "--uninstall")
            self.assertEqual(dry_run.returncode, 0, dry_run.stderr or dry_run.stdout)

            self.assertTrue((skills_dir / "complex-work-orchestration").is_dir())
            self.assertFalse((skills_dir / "complex-work-orchestration.prev").exists())
            self.assertIn("Would move:", dry_run.stdout)


if __name__ == "__main__":
    unittest.main()
