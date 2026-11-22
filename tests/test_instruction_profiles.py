import hashlib
import json
import os
import re
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "manage_instruction_profile.py"
OPERATOR_GUIDE = ROOT / "references" / "cwo-system-prompt.md"
PROMPT = ROOT / "prompts" / "cwo-architect.md"
LAUNCHER = ROOT / "scripts" / "cwo-codex"
README = ROOT / "README.md"
APPROVED_PROMPT_SHA256 = "8c0f2c9d7bf50490a7795ad113383518e3c7236bee3717950feeddf656ce9a4f"


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
            common = ("--codex-home", str(home), "--launcher-dir", str(launcher_dir))
            installed = json.loads(self.run_cli("install", *common).stdout)
            self.assertEqual(installed["profiles"], ["architect"])
            self.assertFalse(installed["default_profile_changed"])
            self.assertFalse((home / "config.toml").exists())
            self.assertEqual(
                [path.name for path in home.glob("*.config.toml")],
                ["cwo-architect.config.toml"],
            )
            prompt = home / "prompts" / "cwo-architect.md"
            profile = home / "cwo-architect.config.toml"
            self.assertEqual(
                tomllib.loads(profile.read_text(encoding="utf-8")),
                {"model_instructions_file": str(prompt.resolve())},
            )
            launcher = launcher_dir / "cwo-codex"
            self.assertTrue(os.access(launcher, os.X_OK))

            verified = json.loads(self.run_cli("verify", *common).stdout)
            self.assertTrue(verified["ok"])
            self.assertEqual(verified["profiles"], ["architect"])

            removed = json.loads(self.run_cli("remove", *common).stdout)
            self.assertEqual(removed["profiles"], ["architect"])
            self.assertFalse(removed["default_profile_changed"])
            self.assertFalse(profile.exists())
            self.assertFalse(prompt.exists())
            self.assertFalse(launcher.exists())

    def test_modified_profile_requires_force_to_overwrite_or_remove(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            common = (
                "--profile", "architect", "--codex-home", str(home),
                "--launcher-dir", str(home / "bin"),
            )
            self.run_cli("install", *common)
            profile = home / "cwo-architect.config.toml"
            profile.write_text("locally modified\n", encoding="utf-8")
            self.run_cli("verify", *common, expected=2)
            self.run_cli("install", *common, expected=2)
            self.assertEqual(profile.read_text(encoding="utf-8"), "locally modified\n")
            self.run_cli("remove", *common, expected=2)
            self.assertTrue(profile.exists())
            self.run_cli("remove", *common, "--force")
            self.assertFalse(profile.exists())

    def test_architect_profile_preserves_other_defaults_and_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            common = ("--codex-home", str(home), "--launcher-dir", str(home / "bin"))
            unrelated = {
                home / "config.toml": b"# Default Codex settings\n",
                home / "cwo-sol-operator-e.config.toml": b"# Existing legacy profile\n",
                home / "cwo-sol-overlay-experimental.config.toml": b"# Existing legacy overlay\n",
            }
            for path, content in unrelated.items():
                path.write_bytes(content)
            self.run_cli("install", "--profile", "architect", *common)
            self.run_cli("verify", "--profile", "architect", *common)
            self.run_cli("remove", "--profile", "architect", *common)
            for path, content in unrelated.items():
                self.assertEqual(path.read_bytes(), content)

    def test_operator_guide_commands_and_discoverability_do_not_drift(self) -> None:
        guide = OPERATOR_GUIDE.read_text(encoding="utf-8")
        for command in (
            "python3 scripts/manage_instruction_profile.py install --profile architect",
            "python3 scripts/manage_instruction_profile.py verify --profile architect",
            'cwo-codex -C "$PWD"',
            'codex --profile cwo-architect -C "$PWD"',
            "python3 scripts/manage_instruction_profile.py remove --profile architect",
        ):
            self.assertIn(command, guide)
        self.assertIn(
            "](references/cwo-system-prompt.md)",
            README.read_text(encoding="utf-8"),
        )

    def test_installed_prompt_equals_the_approved_source_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            self.run_cli(
                "install", "--profile", "architect", "--codex-home", str(home),
                "--launcher-dir", str(home / "bin"),
            )
            source = PROMPT.read_bytes()
            self.assertEqual((home / "prompts" / PROMPT.name).read_bytes(), source)
            self.assertEqual(hashlib.sha256(source).hexdigest(), APPROVED_PROMPT_SHA256)

    def test_candidate_e_archive_preserves_qualified_prompt_evidence(self) -> None:
        archived = ROOT / "prompts" / "archive"
        qualified = (archived / "cwo-sol-operator-e-v5-qualified.md").read_bytes()
        final = (archived / "cwo-sol-operator-e.md").read_bytes()
        self.assertEqual(
            hashlib.sha256(qualified).hexdigest(),
            "75b3bdf7624d7e3913f2879f4a20306c74805ad8409ce785597da67e1011c3f8",
        )
        self.assertEqual(
            hashlib.sha256(final).hexdigest(),
            "78a322fe1b5e72ba7f1d1a4253230f90fef37a372ed1334ec00c1e20647874b8",
        )

    def test_architect_prompt_contains_no_model_ids(self) -> None:
        model_id = re.compile(
            r"\b(?:gpt-\d+(?:\.\d+)*(?:-[a-z0-9]+)*|gpt-reserve|"
            r"gpt-daybreak-blue-latest|codex-auto-review)\b",
            re.IGNORECASE,
        )
        self.assertNotRegex(PROMPT.read_text(encoding="utf-8"), model_id)

    def test_architect_prompt_contains_no_authority_tokens(self) -> None:
        """Cover F1 and F2 only because no phrase may act as a password for authority."""
        quoted_steering = r"""["'“‘`](?:proceed|go|repair until complete)["'”’`]"""
        quoted_phrase = r"""["'“‘`][^"'”’`]{1,60}["'”’`]"""
        authority = r"\b(?:grant|remove|authoriz|permit|enabl|disabl|switch|toggl)\w*\b"
        autonomy_switch = r"\b(?:enabl|disabl|switch|toggl)\w*[^.!?]{0,20}\bautonomy\b"
        patterns = (
            r"\b(?:bypass|pre[- ]?authoriz(?:e|ed|ation)|step (?:over|around)|full_auto)\b",
            r"\b(?:skip|cut|remove|blocking)\s+(?:the\s+)?ceremony\b|\bceremony\s+blocks\b",
            rf"{quoted_steering}[^.!?]{{0,40}}{authority}",
            rf"{authority}[^.!?]{{0,40}}{quoted_steering}",
            rf"{quoted_phrase}[^.!?]{{0,40}}{autonomy_switch}",
            rf"{autonomy_switch}[^.!?]{{0,40}}{quoted_phrase}",
        )
        prompt = " ".join(PROMPT.read_text(encoding="utf-8").split())
        for pattern in patterns:
            self.assertNotRegex(prompt, re.compile(pattern, re.IGNORECASE))

    def test_launcher_selects_profile_and_forwards_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_codex = root / "codex"
            fake_codex.write_text(
                "#!/usr/bin/env sh\nprintf '%s\\n' \"$@\"\n",
                encoding="utf-8",
            )
            fake_codex.chmod(0o755)
            env = {**os.environ, "PATH": f"{root}{os.pathsep}{os.environ['PATH']}"}
            result = subprocess.run(
                [str(LAUNCHER), "-C", "/tmp/example project", "--ephemeral"],
                cwd=root,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines()[:2], ["--profile", "cwo-architect"])
            sol = json.loads((ROOT / "policy" / "model-roles.yaml").read_text())["roles"]["sol"]
            self.assertEqual(
                result.stdout.splitlines(),
                [
                    "--profile", "cwo-architect",
                    "-c", f"model={json.dumps(sol.get('pin', sol['current']))}",
                    "-c", f"model_reasoning_effort={json.dumps(sol['reasoning_effort'])}",
                    "-c", f"service_tier={json.dumps(sol['service_tier'])}",
                    "-C", "/tmp/example project", "--ephemeral",
                ],
            )


if __name__ == "__main__":
    unittest.main()
