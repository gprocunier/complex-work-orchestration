"""Exercise delegation setup with fake login and isolated startup effects."""
from __future__ import annotations

from contextlib import ExitStack, redirect_stderr, redirect_stdout
from io import StringIO
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import host_records  # noqa: E402
import registered_n1_qualification as qualification  # noqa: E402


class DelegationSetupTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.root = Path(workspace.name)
        self.account = self.root / "account"
        self.account.mkdir(mode=0o700)
        self.main_home = self.account / "interactive-codex"
        self.main_home.mkdir(mode=0o700)
        self.main_auth = self.main_home / "auth.json"
        self.main_auth.write_text("EXAMPLE original interactive auth")
        self.main_auth.chmod(0o600)
        self.worker_home = self.account / "worker-codex"
        self.binary = self.root / "codex"
        self.binary.touch(mode=0o700)
        self.store = host_records.HostRecordStore.for_tests(self.root / "host-state")

    def invoke(self, worker_home=None, *, login_exit=0, startup_error=None, namespace_exited=True,
               binary_on_path=None, during_startup=None):
        import setup_delegation as setup

        def fake_login(command, *, env, check):
            self.probe.return_value.read_configuration.assert_called_once()
            self.assertEqual(command, [str(self.binary), "-c", 'cli_auth_credentials_store="file"',
                                       "login", "--device-auth"])
            self.assertTrue(check)
            if login_exit:
                raise subprocess.CalledProcessError(login_exit, command)
            isolated = Path(env["CODEX_HOME"])
            self.assertEqual(isolated, self.worker_home)
            self.assertNotEqual(isolated, self.main_home)
            auth = isolated / "auth.json"
            auth.write_text("EXAMPLE dedicated worker auth")
            auth.chmod(0o600)

        with ExitStack() as stack:
            stack.enter_context(host_records.using_test_store(self.store))
            stack.enter_context(patch.object(qualification, "_controller_home", return_value=self.account))
            stack.enter_context(patch.dict(os.environ, {"CODEX_HOME": str(self.account / ".codex")}))
            stack.enter_context(patch.object(setup.shutil, "which", return_value=str(binary_on_path or self.binary)))
            self.login = stack.enter_context(patch.object(setup.subprocess, "run", side_effect=fake_login))
            self.probe = stack.enter_context(patch.object(setup, "SelectedNativeProbe"))
            observation = {
                "responses": {"initialize": {"id": 1, "result": {}}},
                "accepted_output": False,
                "cleanup": {"namespace_exited": namespace_exited, "accepted_output": False},
            }
            def check_startup():
                if startup_error is not None:
                    raise startup_error
                if during_startup is not None:
                    during_startup()
                return observation
            self.probe.return_value.read_configuration.side_effect = check_startup
            self.out = stack.enter_context(redirect_stdout(StringIO()))
            self.err = stack.enter_context(redirect_stderr(StringIO()))
            code = setup.main(["--codex-home", str(self.main_home),
                               "--worker-home", str(worker_home or self.worker_home)])
        self.assertEqual(self.main_auth.read_text(), "EXAMPLE original interactive auth")
        return code

    def configured(self):
        from registered_worker_login_config import read_worker_login_home

        with host_records.using_test_store(self.store):
            return read_worker_login_home()

    def test_fake_device_login_checks_startup_then_saves_only_worker_path(self):
        self.assertEqual(self.invoke(), 0, self.err.getvalue())
        self.login.assert_called_once()
        self.probe.assert_called_once_with(codex=self.binary)
        self.assertEqual(stat.S_IMODE(self.worker_home.stat().st_mode), 0o700)
        self.assertEqual(self.configured(), self.worker_home)
        self.assertIn("startup", self.out.getvalue())
        self.assertNotIn("EXAMPLE dedicated worker auth", self.out.getvalue())

    def test_explicit_main_login_is_refused_before_any_effect(self):
        self.assertEqual(self.invoke(self.main_home), 1)
        self.login.assert_not_called()
        self.probe.assert_not_called()
        self.assertIsNone(self.configured())
        self.assertIn("main Codex home", self.err.getvalue())

    def test_login_failure_does_not_publish_setting_after_successful_startup(self):
        self.assertEqual(self.invoke(login_exit=1), 1)
        self.probe.assert_called_once_with(codex=self.binary)
        self.assertIsNone(self.configured())

    def test_startup_failure_does_not_sign_in_or_publish_setting(self):
        self.assertEqual(self.invoke(startup_error=ValueError("EXAMPLE startup fault")), 1)
        self.login.assert_not_called()
        self.assertIsNone(self.configured())

    def test_unconfirmed_startup_cleanup_does_not_publish_setting(self):
        self.assertEqual(self.invoke(namespace_exited=False), 1)
        self.login.assert_not_called()
        self.assertIn("startup or cleanup", self.err.getvalue())
        self.assertIsNone(self.configured())

    def test_setup_reuses_existing_safe_worker_login(self):
        self.assertEqual(self.invoke(), 0, self.err.getvalue())
        self.assertEqual(self.invoke(), 0, self.err.getvalue())
        self.login.assert_not_called()
        self.probe.assert_called_once()
        self.assertEqual(self.configured(), self.worker_home)

    def test_path_alias_uses_the_same_direct_binary_for_startup_and_login(self):
        alias = self.root / "codex-on-path"
        alias.symlink_to(self.binary)
        self.assertEqual(self.invoke(binary_on_path=alias), 0, self.err.getvalue())
        self.probe.assert_called_once_with(codex=self.binary)
        self.login.assert_called_once()

    def test_replaced_worker_path_cannot_redirect_sign_in_after_startup(self):
        def replace_home():
            self.worker_home.rename(self.worker_home.with_name("old-worker"))
            self.worker_home.symlink_to(self.main_home)

        self.assertEqual(self.invoke(during_startup=replace_home), 1)
        self.login.assert_not_called()
        self.assertIsNone(self.configured())

    def test_worker_symlink_to_main_is_refused_before_sign_in(self):
        self.worker_home.symlink_to(self.main_home)
        self.assertEqual(self.invoke(), 1)
        self.login.assert_not_called()
        self.probe.assert_not_called()
        self.assertIsNone(self.configured())

    def test_linked_worker_auth_cannot_use_the_interactive_credential(self):
        self.worker_home.mkdir(mode=0o700)
        (self.worker_home / "auth.json").symlink_to(self.main_auth)
        self.assertEqual(self.invoke(), 1)
        self.login.assert_not_called()
        self.probe.assert_not_called()
        self.assertIsNone(self.configured())

    def test_public_worker_directory_is_refused_without_changing_its_permissions(self):
        self.worker_home.mkdir(mode=0o755)
        self.assertEqual(self.invoke(), 1)
        self.login.assert_not_called()
        self.assertEqual(stat.S_IMODE(self.worker_home.stat().st_mode), 0o755)
        self.assertIsNone(self.configured())


class GuidedInstallerTests(unittest.TestCase):
    def invoke(self, *args, answer="", terminal=False, setup_exit=0):
        with tempfile.TemporaryDirectory() as tmp:
            installers = Path(tmp) / "installer-functions.sh"
            definition, final_call = (ROOT / "scripts/install.sh").read_text().strip().rsplit("\n", 1)
            self.assertEqual(final_call, 'main "$@"')
            installers.write_text(definition + "\n")
            command = r"""
source "$1"
shift
is_interactive() { [ "$ASSUME_YES" -eq 0 ] && [ "$EXAMPLE_TERMINAL" -eq 1 ]; }
detect_codex_home() { printf '%s\n' "/fixture/main codex"; }
prompt_path() { printf '%s\n' "/fixture/skills folder"; }
require_python() { :; }
install_skill() { printf 'EXAMPLE install fixture\n'; }
validate_skill() { :; }
check_installed_skill_drift() { :; }
check_beads() { :; }
uninstall_skill() { printf 'EXAMPLE uninstall fixture\n'; }
python3() {
  printf 'EXAMPLE setup call: %s\n' "$*"
  return "$EXAMPLE_SETUP_EXIT"
}
main "$@"
"""
            return subprocess.run(["bash", "-c", command, "fixture", str(installers), *args],
                                  input=answer + "\n", text=True, capture_output=True,
                                  env={**os.environ, "EXAMPLE_TERMINAL": str(int(terminal)),
                                       "EXAMPLE_SETUP_EXIT": str(setup_exit)}, check=False)

    def test_confirmed_prompt_runs_the_same_standalone_setup(self):
        result = self.invoke(terminal=True, answer="yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[y/N]", result.stdout)
        self.assertIn("EXAMPLE setup call: -B /fixture/skills folder/complex-work-orchestration/scripts/"
                      "setup_delegation.py --codex-home /fixture/main codex", result.stdout)

    def test_decline_and_noninteractive_install_print_command_without_running_it(self):
        for args, terminal, answer in (((), True, "no"), ((), False, "yes"), (("--yes",), True, "yes")):
            with self.subTest(args=args, terminal=terminal):
                result = self.invoke(*args, terminal=terminal, answer=answer)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("setup_delegation.py --codex-home", result.stdout)
                self.assertNotIn("EXAMPLE setup call", result.stdout)

    def test_explicit_setup_works_without_an_installer_prompt(self):
        result = self.invoke("--yes", "--setup-delegation")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("[y/N]", result.stdout)
        self.assertEqual(result.stdout.count("EXAMPLE setup call"), 1)

    def test_explicit_setup_failure_leaves_retry_command(self):
        result = self.invoke("--setup-delegation", setup_exit=1)
        self.assertEqual(result.returncode, 1)
        self.assertIn("The skill is installed.", result.stdout)
        self.assertIn("setup_delegation.py --codex-home", result.stdout)

    def test_dry_run_never_invokes_setup_even_when_requested(self):
        result = self.invoke("--dry-run", "--setup-delegation", terminal=True, answer="yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("worker delegation setup would run", result.stdout)
        self.assertNotIn("[y/N]", result.stdout)
        self.assertNotIn("EXAMPLE setup call", result.stdout)

    def test_uninstall_never_invokes_setup_even_when_requested(self):
        result = self.invoke("--uninstall", "--setup-delegation", terminal=True, answer="yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("EXAMPLE uninstall fixture", result.stdout)
        self.assertNotIn("EXAMPLE install fixture", result.stdout)
        self.assertNotIn("[y/N]", result.stdout)
        self.assertNotIn("EXAMPLE setup call", result.stdout)
