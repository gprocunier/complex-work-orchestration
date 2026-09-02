import json
import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "manage_instruction_profile.py"
GUIDE = ROOT / "references" / "cwo-sol-operator-profile.md"
E_GUIDE = ROOT / "references" / "cwo-candidate-e-operator-profile.md"
C_PROMPT = ROOT / "prompts" / "cwo-sol-operator.md"
E_PROMPT = ROOT / "prompts" / "cwo-sol-operator-e.md"
QUALIFIED_E_PROMPT = ROOT / "prompts" / "archive" / "cwo-sol-operator-e-v5-qualified.md"
LAUNCHER = ROOT / "scripts" / "cwo-codex"
CWO_SKILL = ROOT / "SKILL.md"
README = ROOT / "README.md"


class InstructionProfileTests(unittest.TestCase):
    def run_cli(self, *args: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["python", str(SCRIPT), *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, expected, result.stderr or result.stdout)
        return result

    def test_install_verify_remove_does_not_create_default_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            launcher_dir = home / ".local" / "bin"
            installed = json.loads(
                self.run_cli(
                    "install",
                    "--codex-home",
                    str(home),
                    "--launcher-dir",
                    str(launcher_dir),
                ).stdout
            )
            self.assertFalse(installed["default_profile_changed"])
            self.assertFalse((home / "config.toml").exists())
            self.assertTrue((home / "cwo-sol-overlay-experimental.config.toml").is_file())
            operator = home / "cwo-sol-operator-experimental.config.toml"
            self.assertIn(str((home / "prompts" / "cwo-sol-operator.md").resolve()), operator.read_text())

            verified = json.loads(
                self.run_cli(
                    "verify",
                    "--codex-home",
                    str(home),
                    "--launcher-dir",
                    str(launcher_dir),
                ).stdout
            )
            self.assertTrue(verified["ok"])

            removed = json.loads(
                self.run_cli(
                    "remove",
                    "--codex-home",
                    str(home),
                    "--launcher-dir",
                    str(launcher_dir),
                ).stdout
            )
            self.assertFalse(removed["default_profile_changed"])
            self.assertFalse(operator.exists())
            self.assertFalse((home / "prompts" / "cwo-sol-operator.md").exists())

    def test_modified_profile_requires_force_to_overwrite_or_remove(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            self.run_cli("install", "--profile", "overlay", "--codex-home", str(home))
            profile = home / "cwo-sol-overlay-experimental.config.toml"
            profile.write_text("locally modified\n", encoding="utf-8")
            self.run_cli("install", "--profile", "overlay", "--codex-home", str(home), expected=2)
            self.assertEqual(profile.read_text(encoding="utf-8"), "locally modified\n")
            self.run_cli("remove", "--profile", "overlay", "--codex-home", str(home), expected=2)
            self.assertTrue(profile.exists())
            self.run_cli("remove", "--profile", "overlay", "--codex-home", str(home), "--force")
            self.assertFalse(profile.exists())

    def test_default_candidate_e_workflow_installs_launcher_without_editing_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            launcher_dir = home / ".local" / "bin"
            installed = json.loads(
                self.run_cli(
                    "install",
                    "--profile",
                    "operator-e",
                    "--codex-home",
                    str(home),
                    "--launcher-dir",
                    str(launcher_dir),
                ).stdout
            )
            self.assertEqual(installed["profiles"], ["operator-e"])
            self.assertFalse(installed["default_profile_changed"])
            self.assertFalse((home / "config.toml").exists())
            self.assertFalse((home / "cwo-sol-overlay-experimental.config.toml").exists())
            self.assertEqual((launcher_dir / "cwo-codex").read_bytes(), LAUNCHER.read_bytes())

            verified = json.loads(
                self.run_cli(
                    "verify", "--profile", "operator-e", "--codex-home", str(home),
                    "--launcher-dir", str(launcher_dir)
                ).stdout
            )
            self.assertTrue(verified["ok"])
            self.assertEqual(verified["profiles"], ["operator-e"])

            removed = json.loads(
                self.run_cli(
                    "remove", "--profile", "operator-e", "--codex-home", str(home),
                    "--launcher-dir", str(launcher_dir)
                ).stdout
            )
            self.assertEqual(removed["profiles"], ["operator-e"])
            self.assertFalse(removed["default_profile_changed"])
            self.assertFalse((home / "config.toml").exists())
            self.assertFalse((home / "cwo-sol-operator-e.config.toml").exists())
            self.assertFalse((home / "prompts" / "cwo-sol-operator-e.md").exists())
            self.assertFalse((launcher_dir / "cwo-codex").exists())

    def test_operator_guide_commands_and_discoverability_do_not_drift(self) -> None:
        guide = E_GUIDE.read_text(encoding="utf-8")
        for command in (
            "python3 scripts/manage_instruction_profile.py install --profile operator-e",
            "python3 scripts/manage_instruction_profile.py verify --profile operator-e",
            'cwo-codex -C "$PWD"',
            'codex --profile cwo-sol-operator-e -C "$PWD"',
            "python3 scripts/manage_instruction_profile.py remove --profile operator-e",
        ):
            self.assertIn(command, guide)
        self.assertIn("at the start of a new Codex session", guide)
        self.assertIn("does not edit `config.toml`", guide)
        self.assertIn("trusted CWO enforcement", guide)
        self.assertIn(
            "[Candidate E CWO operator profile](references/cwo-candidate-e-operator-profile.md)",
            README.read_text(encoding="utf-8"),
        )

    def test_candidate_e_install_verify_remove_preserves_other_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / ".codex"
            launcher_dir = root / ".local" / "bin"
            common = (
                "--profile",
                "operator-e",
                "--codex-home",
                str(home),
                "--launcher-dir",
                str(launcher_dir),
            )

            installed = json.loads(self.run_cli("install", *common).stdout)
            self.assertEqual(installed["profiles"], ["operator-e"])
            self.assertFalse(installed["default_profile_changed"])
            self.assertFalse((home / "config.toml").exists())
            self.assertFalse((home / "cwo-sol-operator-experimental.config.toml").exists())

            prompt = home / "prompts" / "cwo-sol-operator-e.md"
            profile = home / "cwo-sol-operator-e.config.toml"
            self.assertEqual(prompt.read_bytes(), E_PROMPT.read_bytes())
            self.assertIn('model = "gpt-5.6-sol"', profile.read_text(encoding="utf-8"))
            self.assertNotIn("model_reasoning_effort", profile.read_text(encoding="utf-8"))
            self.assertIn(str(prompt.resolve()), profile.read_text(encoding="utf-8"))
            self.assertEqual((launcher_dir / "cwo-codex").read_bytes(), LAUNCHER.read_bytes())

            verified = json.loads(self.run_cli("verify", *common).stdout)
            self.assertTrue(verified["ok"])
            self.assertTrue(all(check["ok"] for check in verified["checks"]))

            removed = json.loads(self.run_cli("remove", *common).stdout)
            self.assertEqual(removed["profiles"], ["operator-e"])
            self.assertFalse(prompt.exists())
            self.assertFalse(profile.exists())
            self.assertFalse((launcher_dir / "cwo-codex").exists())

    def test_candidate_e_profile_is_interactive_and_documented(self) -> None:
        prompt = E_PROMPT.read_text(encoding="utf-8")
        for expected in (
            "Acceptance closure",
            "Semantic and decision closure",
            "Complete change transactions",
            "Finite execution and recovery",
            "Distinguish candidate or product failure from harness",
        ):
            self.assertIn(expected, prompt)
        for evaluation_only in (
            "Return exactly one JSON object",
            "Do not call tools",
            "campaign_id",
            "Frozen inspection",
        ):
            self.assertNotIn(evaluation_only, prompt)

        guide = E_GUIDE.read_text(encoding="utf-8")
        for command in (
            "python3 scripts/manage_instruction_profile.py install --profile operator-e",
            "python3 scripts/manage_instruction_profile.py verify --profile operator-e",
            'codex --profile cwo-sol-operator-e -C "$PWD"',
            "python3 scripts/manage_instruction_profile.py remove --profile operator-e",
        ):
            self.assertIn(command, guide)
        self.assertIn("prompts/cwo-sol-operator-e.md", CWO_SKILL.read_text(encoding="utf-8"))
        self.assertIn(
            "[Candidate E CWO operator profile](references/cwo-candidate-e-operator-profile.md)",
            README.read_text(encoding="utf-8"),
        )
        combined = "\n".join(
            (
                README.read_text(encoding="utf-8"),
                CWO_SKILL.read_text(encoding="utf-8"),
                guide,
            )
        )
        self.assertNotIn("interim incumbent", combined)
        self.assertIn("fewest recorded tokens", combined)

    def test_candidate_e_protocol_repair_preserves_qualified_prompt_evidence(self) -> None:
        qualified = QUALIFIED_E_PROMPT.read_bytes()
        active = E_PROMPT.read_text(encoding="utf-8")
        self.assertEqual(
            hashlib.sha256(qualified).hexdigest(),
            "75b3bdf7624d7e3913f2879f4a20306c74805ad8409ce785597da67e1011c3f8",
        )
        self.assertNotEqual(E_PROMPT.read_bytes(), qualified)
        normalized = " ".join(active.split())
        for expected in (
            "Frozen protocol fidelity",
            "For experiments these bound fields are scope boundaries, not summaries.",
            "does not authorize a replacement benchmark",
            "Explicit replacement authority starts a new protocol",
            "Revalidate the protocol lock before every candidate or model call",
        ):
            self.assertIn(expected, normalized)
        guide = E_GUIDE.read_text(encoding="utf-8")
        self.assertIn("post-v5 repair", guide)
        self.assertIn("No new model comparison has qualified", guide)
        self.assertIn("frozen-protocol-lock.md", guide)
        self.assertIn("does not set `model_reasoning_effort`", guide)
        self.assertIn("post-v5 frozen-protocol repair", README.read_text(encoding="utf-8"))
        self.assertEqual(
            hashlib.sha256(E_PROMPT.read_bytes()).hexdigest(),
            "ce85010acb60ea9fafd81f84790524a86f685067b65f86c352e07a5d3367ef67",
        )

    def test_default_e_launcher_selects_profile_and_forwards_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_codex = fake_bin / "codex"
            fake_codex.write_text(
                "#!/usr/bin/env sh\nprintf '%s\\n' \"$@\"\n",
                encoding="utf-8",
            )
            fake_codex.chmod(0o755)
            env = dict(os.environ)
            env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
            result = subprocess.run(
                [str(LAUNCHER), "-C", "/tmp/example", "--ephemeral"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                result.stdout.splitlines(),
                [
                    "--profile",
                    "cwo-sol-operator-e",
                    "-C",
                    "/tmp/example",
                    "--ephemeral",
                ],
            )


if __name__ == "__main__":
    unittest.main()
