from __future__ import annotations

from copy import deepcopy
import json
import os
import shlex
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


    def test_install_dry_run_uses_lexical_backup_for_missing_parent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            parent = Path(tmpdir) / "missing parent"
            skills_dir = parent / "skills"
            result = self.run_installer("--skills-dir", str(skills_dir), "--yes", "--dry-run")
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            self.assertIn(f"Backup directory: {parent / 'skill-backups'}", result.stdout)
            self.assertFalse(parent.exists())

    def test_installer_copies_public_security_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            skills_dir = Path(tmpdir) / "skills"
            result = self.run_installer("--skills-dir", str(skills_dir), "--yes")
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            target = skills_dir / "complex-work-orchestration" / "SECURITY.md"
            self.assertEqual(target.read_bytes(), (ROOT / "SECURITY.md").read_bytes())

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

    def test_installer_copies_instruction_prompts_and_qualified_archive(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            skills_dir = Path(tmpdir) / "skills"
            install = self.run_installer("--skills-dir", str(skills_dir), "--yes")
            self.assertEqual(install.returncode, 0, install.stderr or install.stdout)

            prompts = skills_dir / "complex-work-orchestration" / "prompts"
            self.assertTrue((prompts / "cwo-architect.md").is_file())
            self.assertTrue((prompts / "archive" / "cwo-sol-operator-e-v5-qualified.md").is_file())


    def test_install_offers_only_architect_and_launches_with_installed_role_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir) / "operator home"
            codex_home = home / "codex"
            skills_dir = home / "custom skills"
            bin_dir = home / "bin"
            bin_dir.mkdir(parents=True)
            fake_codex = bin_dir / "codex"
            fake_codex.write_text("#!/bin/sh\nprintf '%s\\n' \"$PWD\" \"$CODEX_HOME\" \"$@\"\n", encoding="utf-8")
            fake_codex.chmod(0o755)
            env = {
                **os.environ, "HOME": str(home), "CODEX_HOME": str(codex_home),
                "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            }
            install = subprocess.run(
                [str(ROOT / "scripts" / "install.sh"), "--skills-dir", str(skills_dir), "--yes"],
                cwd=home, env=env, text=True, capture_output=True, check=False,
            )
            self.assertEqual(install.returncode, 0, install.stderr or install.stdout)
            self.assertFalse(codex_home.exists())
            launcher = home / ".local" / "bin" / "cwo-codex"
            self.assertFalse(launcher.exists())

            offers = [shlex.split(line) for line in install.stdout.splitlines()
                      if "manage_instruction_profile.py install" in line]
            skill = skills_dir / "complex-work-orchestration"
            self.assertEqual(offers, [[
                "python3", str(skill / "scripts" / "manage_instruction_profile.py"),
                "install", "--profile", "architect", "--codex-home", str(codex_home),
            ]])
            opt_in = subprocess.run(offers[0], cwd=home, env=env, capture_output=True, text=True, check=False)
            self.assertEqual(opt_in.returncode, 0, opt_in.stderr)

            routing_file = skill / "policy" / "model-roles.yaml"
            policy = json.loads(routing_file.read_text(encoding="utf-8"))
            policy["roles"]["sol"].update(pin="gpt-9.6-sol", reasoning_effort="high", service_tier="fast")
            routing_file.write_text(json.dumps(policy), encoding="utf-8")
            launch = subprocess.run(
                [str(launcher), "-C", str(home), "--ephemeral"],
                cwd=home, env=env, text=True, capture_output=True, check=False,
            )
            self.assertEqual(launch.returncode, 0, launch.stderr)
            self.assertEqual(launch.stdout.splitlines(), [
                str(home), str(codex_home),
                "--profile", "cwo-architect", "-c", 'model="gpt-9.6-sol"',
                "-c", 'model_reasoning_effort="high"', "-c", 'service_tier="fast"',
                "-C", str(home), "--ephemeral",
            ])
            for missing in ("reasoning_effort", "service_tier"):
                with self.subTest(missing=missing):
                    incomplete = deepcopy(policy)
                    del incomplete["roles"]["sol"][missing]
                    routing_file.write_text(json.dumps(incomplete), encoding="utf-8")
                    refused = subprocess.run(
                        [str(launcher)], cwd=home, env=env, text=True, capture_output=True, check=False,
                    )
                    self.assertNotEqual(refused.returncode, 0)
                    self.assertIn(f"sol {missing}", refused.stderr)
                    self.assertEqual(refused.stdout, "")
            self.assertFalse((codex_home / "config.toml").exists())

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


    def test_install_dry_run_does_not_create_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            skills_dir = Path(tmpdir) / "skills"
            dry_run = self.run_installer("--skills-dir", str(skills_dir), "--yes", "--dry-run")
            self.assertEqual(dry_run.returncode, 0, dry_run.stderr or dry_run.stdout)

            self.assertFalse((skills_dir / "complex-work-orchestration").exists())
            self.assertIn("Would create staging install", dry_run.stdout)


if __name__ == "__main__":
    unittest.main()
