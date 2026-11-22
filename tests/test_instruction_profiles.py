import json
import hashlib
import os
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "manage_instruction_profile.py"
GUIDE = ROOT / "references" / "cwo-sol-operator-profile.md"
OPERATOR_GUIDE = ROOT / "references" / "cwo-system-prompt.md"
C_PROMPT = ROOT / "prompts" / "cwo-sol-operator.md"
E_PROMPT = ROOT / "prompts" / "cwo-sol-operator-e.md"
QUALIFIED_E_PROMPT = ROOT / "prompts" / "archive" / "cwo-sol-operator-e-v5-qualified.md"
LAUNCHER = ROOT / "scripts" / "cwo-codex"
CWO_SKILL = ROOT / "SKILL.md"
README = ROOT / "README.md"
ROUTING_POLICY = Path("policy/execution-environments.yaml")


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
            overlay = home / "cwo-sol-overlay-experimental.config.toml"
            self.assertEqual(tomllib.loads(overlay.read_text()), {
                "model": "gpt-5.6-sol",
                "model_reasoning_effort": "max",
                "developer_instructions": (ROOT / "prompts" / "cwo-sol-overlay.md").read_text(),
            })
            operator = home / "cwo-sol-operator-experimental.config.toml"
            self.assertEqual(tomllib.loads(operator.read_text()), {
                "model": "gpt-5.6-sol",
                "model_reasoning_effort": "max",
                "model_instructions_file": str((home / "prompts" / "cwo-sol-operator.md").resolve()),
            })

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
        guide = OPERATOR_GUIDE.read_text(encoding="utf-8")
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
        self.assertIn("trusted cwo enforcement", guide.lower())
        self.assertIn(
            "[CWO system prompt](references/cwo-system-prompt.md)",
            README.read_text(encoding="utf-8"),
        )

    def test_candidate_e_install_verify_remove_preserves_other_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / ".codex"
            launcher_dir = root / ".local" / "bin"
            home.mkdir()
            config = home / "config.toml"
            defaults = 'model_reasoning_effort = "high"\n'
            config.write_text(defaults)
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
            self.assertEqual(config.read_text(), defaults)
            self.assertFalse((home / "cwo-sol-operator-experimental.config.toml").exists())

            prompt = home / "prompts" / "cwo-sol-operator-e.md"
            profile = home / "cwo-sol-operator-e.config.toml"
            self.assertEqual(prompt.read_bytes(), E_PROMPT.read_bytes())
            routing = json.loads((ROOT / ROUTING_POLICY).read_bytes())
            model = routing["profiles"]["connected-codex"]["role_bindings"]["architect"]["model"]
            self.assertEqual(tomllib.loads(profile.read_text()), {
                "model": model,
                "model_instructions_file": str(prompt.resolve()),
            })
            self.assertEqual((launcher_dir / "cwo-codex").read_bytes(), LAUNCHER.read_bytes())

            verified = json.loads(self.run_cli("verify", *common).stdout)
            self.assertTrue(verified["ok"])
            self.assertTrue(all(check["ok"] for check in verified["checks"]))
            installed_files = {file["path"]: file for file in installed["files"]}
            prompt_check = next(check for check in verified["checks"] if check["path"] == str(prompt))
            digest = hashlib.sha256(E_PROMPT.read_bytes()).hexdigest()
            self.assertEqual(installed_files[str(prompt)]["sha256"], digest)
            self.assertEqual(prompt_check["expected_sha256"], digest)
            self.assertEqual(prompt_check["actual_sha256"], digest)

            prompt.write_bytes(E_PROMPT.read_bytes() + b"\n")
            drift = json.loads(self.run_cli("verify", *common, expected=2).stdout)
            self.assertFalse(drift["ok"])
            self.assertEqual([check["path"] for check in drift["checks"] if not check["ok"]], [str(prompt)])
            prompt.write_bytes(E_PROMPT.read_bytes())

            removed = json.loads(self.run_cli("remove", *common).stdout)
            self.assertEqual(removed["profiles"], ["operator-e"])
            self.assertFalse(prompt.exists())
            self.assertFalse(profile.exists())
            self.assertFalse((launcher_dir / "cwo-codex").exists())
            self.assertEqual(config.read_text(), defaults)

    def test_operator_e_uses_selected_source_routing_policy_and_refuses_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            for original in (ROOT / ROUTING_POLICY, E_PROMPT, LAUNCHER):
                target = source / original.relative_to(ROOT)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(original.read_bytes())
            home = root / "codex"
            launcher_dir = root / "bin"
            args = ("--profile", "operator-e", "--source-root", str(source),
                    "--codex-home", str(home), "--launcher-dir", str(launcher_dir))
            path = source / ROUTING_POLICY
            policy = json.loads(path.read_bytes())
            architect = policy["profiles"]["connected-codex"]["role_bindings"]["architect"]
            original_model = architect.pop("model")
            path.write_text(json.dumps(policy))

            self.run_cli("install", *args, expected=2)
            self.assertFalse(home.exists())
            self.assertFalse(launcher_dir.exists())

            architect["model"] = original_model
            path.write_text(json.dumps(policy))
            self.run_cli("install", *args)
            profile = home / "cwo-sol-operator-e.config.toml"
            self.assertEqual(tomllib.loads(profile.read_text())["model"], original_model)

            architect["model"] = "gpt-9.9-sol"
            path.write_text(json.dumps(policy))
            stale = json.loads(self.run_cli("verify", *args, expected=2).stdout)
            self.assertEqual([check["path"] for check in stale["checks"] if not check["ok"]], [str(profile)])
            self.run_cli("install", *args, expected=2)
            self.assertEqual(tomllib.loads(profile.read_text())["model"], original_model)
            self.run_cli("install", *args, "--force")
            self.assertEqual(tomllib.loads(profile.read_text())["model"], architect["model"])
            self.run_cli("verify", *args)

    def test_candidate_e_profile_is_interactive_and_documented(self) -> None:
        prompt = E_PROMPT.read_text(encoding="utf-8")
        normalized = " ".join(prompt.split())
        for expected in (
            "Start with the next useful action.",
            "correct recoverable failures within the recorded scope and allowance.",
            "Diagnose whether a failure came from the product, harness, transport, or verifier.",
            "Continue independent authorized work",
        ):
            self.assertIn(expected, normalized)
        for evaluation_only in (
            "Return exactly one JSON object",
            "Do not call tools",
            "campaign_id",
            "Frozen inspection",
        ):
            self.assertNotIn(evaluation_only, prompt)

        guide = OPERATOR_GUIDE.read_text(encoding="utf-8")
        for command in (
            "python3 scripts/manage_instruction_profile.py install --profile operator-e",
            "python3 scripts/manage_instruction_profile.py verify --profile operator-e",
            'codex --profile cwo-sol-operator-e -C "$PWD"',
            "python3 scripts/manage_instruction_profile.py remove --profile operator-e",
        ):
            self.assertIn(command, guide)
        self.assertIn("prompts/cwo-sol-operator-e.md", CWO_SKILL.read_text(encoding="utf-8"))
        self.assertIn(
            "[CWO system prompt](references/cwo-system-prompt.md)",
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
        self.assertIn("optimized for complex project work", combined)
        self.assertNotIn("fewest recorded tokens", combined)

    def test_frozen_protocol_guidance_preserves_qualified_prompt_evidence(self) -> None:
        qualified = QUALIFIED_E_PROMPT.read_bytes()
        active = E_PROMPT.read_bytes()
        self.assertEqual(
            hashlib.sha256(qualified).hexdigest(),
            "75b3bdf7624d7e3913f2879f4a20306c74805ad8409ce785597da67e1011c3f8",
        )
        self.assertNotEqual(active, qualified)
        normalized = " ".join(active.decode().split())
        for expected in (
            "frozen protocol lock before every candidate or model call and after steering, interruption, or compaction.",
            "Continue or repair mechanics within those bindings.",
            "`new-protocol-required` result requires explicitly authorized replacement scope and a new lock",
            "Keep terminal attempts terminal",
            "--require-scoped-continuation",
        ):
            self.assertIn(expected, normalized)
        guide = OPERATOR_GUIDE.read_text(encoding="utf-8")
        history = " ".join(
            (ROOT / "references/candidate-e-qualification-summary.md").read_text().split()
        )
        self.assertIn("Post-v5 repair", history)
        self.assertIn("No new model comparison has qualified", history)
        self.assertIn("frozen-protocol-lock.md", guide)
        self.assertIn("does not set `model_reasoning_effort`", guide)
        self.assertIn("default OpenAI system prompt", README.read_text(encoding="utf-8"))
        self.assertIn(
            f"| `prompts/cwo-sol-operator-e.md` | `{hashlib.sha256(active).hexdigest()}` | Active prompt",
            history,
        )

    def test_active_prompt_keeps_routing_closure_and_evidence_boundaries(self) -> None:
        normalized = " ".join(E_PROMPT.read_text(encoding="utf-8").split())
        self.assertNotRegex(normalized, r"(?i)\bgpt[ -]+\d")
        self.assertNotRegex(normalized, r"(?i)\b(?:stop|halt|pause|reapproval)\b")
        for expected in (
            "Use the routing configuration to resolve current model identities.",
            "`sol` for the lead and architecture",
            "`astra` for stronger independent review",
            "`luna` for primary worker tasks",
            "`terra` for a documented worker escalation",
            "live activation preview, new worker-surface qualification",
            "profile selection cannot clear a source hold",
            "keep the exact prompt SHA-256 and session evidence",
            "Record delivered work awaiting verified acceptance as `pending-acceptance` and leave the Bead open.",
            "current, single-use host acceptance",
            "every blocker and child closed",
            "consumption intent before its first Beads write",
            "Failed writes and reopened tasks leave that acceptance spent.",
            "The shipped review-host producer remains under a source hold.",
            "The narrative CLI records the delivery summary and refuses successful closure.",
        ):
            self.assertIn(expected, normalized)

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
