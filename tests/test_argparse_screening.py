from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Iterator, NamedTuple

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

TOKEN = "hunter2"
DISPATCH = "dispatch_work.py"
GENERATOR = "generate_manual_dispatch_prompt.py"
COMMANDS = (DISPATCH, GENERATOR)
INVALID_SENSITIVITY = (
    "argument --data-sensitivity: invalid value (value withheld); choose from public, redacted, internal, restricted"
)
UNRECOGNIZED = "unrecognized arguments (values withheld)"
AMBIGUOUS = "ambiguous option (value withheld)"
OVERSIZED = "@OVERSIZED@"

_NETWORK_SPIES = r"""def record(kind):
    with open(spy_log, "a", encoding="utf-8") as handle:
        handle.write(kind + "\n")

def network_spy(kind):
    def spy(*args, **kwargs):
        record(kind)
        raise OSError("network disabled by the test")
    return spy

socket.socket.connect = network_spy("socket.connect")
socket.socket.connect_ex = network_spy("socket.connect_ex")
socket.socket.sendto = network_spy("socket.sendto")
socket.create_connection = network_spy("socket.create_connection")
socket.getaddrinfo = network_spy("socket.getaddrinfo")

"""

_AUDIT_SPY = r"""def audit_spy(*args, **kwargs):
    record("audit.record_audit_event")
    return real_record_audit_event(*args, **kwargs)

audit.record_audit_event = audit_spy
"""

# Runs a command as __main__ in this child process after installing spies on every way it could
# reach the network and on its audit writer. A spy records the attempt in the spy log and fails.
# OVERSIZED in an argument becomes a run one byte past the screening limit: such an argument
# cannot pass through exec, whose per-argument limit is far smaller.
DRIVER = (r"""
import os, runpy, socket, sys
spy_log = os.environ["ARGPARSE_TEST_SPY_LOG"]

""" + _NETWORK_SPIES + r"""script = sys.argv[1]
sys.path.insert(0, os.path.dirname(os.path.realpath(script)))
import cwo_core.audit as audit
from cwo_core.policy import load_policy
real_record_audit_event = audit.record_audit_event

""" + _AUDIT_SPY + r"""limit = int(load_policy("outbound-screening").get("limits", {}).get("max_input_bytes", 8 * 1024 * 1024))
oversized = "x" * (limit + 1)
sys.argv = [script] + [argument.replace("@OVERSIZED@", oversized) for argument in sys.argv[2:]]
runpy.run_path(script, run_name="__main__")
""")

# A parser whose type function raises a screening refusal, as one that screens its value would.
REFUSING_TYPE = (r"""
import os, socket, sys
sys.path.insert(0, sys.argv[1])
from cwo_core.outbound_screen import OutboundRefused, ScreeningArgumentParser
spy_log = os.environ["ARGPARSE_TEST_SPY_LOG"]

""" + _NETWORK_SPIES + r"""import cwo_core.audit as audit
real_record_audit_event = audit.record_audit_event

""" + _AUDIT_SPY + r"""
def refusing(value):
    raise OutboundRefused("outbound screening refused REFUSAL-SENTINEL")

parser = ScreeningArgumentParser("refusing_type")
parser.add_argument("--value", type=refusing)
parser.parse_args(sys.argv[2:])
print("parsed")
""")


class ParserRefusalCase(NamedTuple):
    original: str
    scripts: tuple[str, ...]
    arguments: list[str]
    diagnostic: str
    secrets: tuple[str, ...]
    spied_only: bool = False


def _parser_refusal_rows() -> Iterator[ParserRefusalCase]:
    yield ParserRefusalCase('test_invalid_choice_with_authorization_header_is_withheld', COMMANDS, ["--data-sensitivity", f"Authorization: Bearer {TOKEN}", "test task"], INVALID_SENSITIVITY, (TOKEN, "Bearer"), False)

    yield ParserRefusalCase('test_invalid_choice_with_password_assignment_is_withheld', COMMANDS, ["--data-sensitivity", f"password={TOKEN}", "test task"], INVALID_SENSITIVITY, (TOKEN, "password="), False)

    yield ParserRefusalCase('test_clean_invalid_choice_is_reported_without_its_value', COMMANDS, ["--data-sensitivity", "bogus", "test task"], INVALID_SENSITIVITY, ("bogus",), False)

    yield ParserRefusalCase('test_numeric_conversion_error_with_credential_is_withheld', (DISPATCH,), ["--local-max-tokens", f"token={TOKEN}", "test task"], "argument --local-max-tokens: invalid value (value withheld)", (TOKEN, "token="), False)

    yield ParserRefusalCase('test_numeric_conversion_error_with_credential_is_withheld', (DISPATCH,), ["--local-timeout", f"Authorization: Bearer {TOKEN}", "test task"], "argument --local-timeout: invalid value (value withheld)", (TOKEN, "Bearer"), False)

    yield ParserRefusalCase('test_clean_numeric_conversion_error_is_reported_without_its_value', (DISPATCH,), ["--local-max-tokens", "bogus", "test task"], "argument --local-max-tokens: invalid value (value withheld)", ("bogus",), False)

    yield ParserRefusalCase('test_clean_numeric_conversion_error_is_reported_without_its_value', (GENERATOR,), ["--local-max-tokens", "bogus", "test task"], UNRECOGNIZED, ("bogus", "--local-max-tokens"), False)

    yield ParserRefusalCase('test_unknown_option_with_credential_is_withheld', COMMANDS, [f"--api-key={TOKEN}", "test task"], UNRECOGNIZED, (TOKEN, "--api-key"), False)

    yield ParserRefusalCase('test_unknown_option_with_credential_is_withheld', COMMANDS, ["--authorization", f"Bearer {TOKEN}", "test task"], UNRECOGNIZED, (TOKEN, "Bearer", "--authorization"), False)

    yield ParserRefusalCase('test_ambiguous_option_with_credential_is_withheld', (DISPATCH,), [f"--local=password={TOKEN}", "test task"], AMBIGUOUS, (TOKEN, "password="), False)

    yield ParserRefusalCase('test_ambiguous_option_with_credential_is_withheld', (GENERATOR,), [f"--allow=password={TOKEN}", "test task"], AMBIGUOUS, (TOKEN, "password="), False)

    yield ParserRefusalCase('test_value_given_to_a_flag_is_withheld', COMMANDS, [f"--json=password={TOKEN}", "test task"], "argument --json: unexpected value (value withheld)", (TOKEN, "password="), False)

    yield ParserRefusalCase('test_missing_value_names_only_the_option', COMMANDS, ["test task", "--data-sensitivity"], "argument --data-sensitivity: expected one argument", (), False)

    run = "x" * 64
    yield ParserRefusalCase('test_argument_past_the_screening_limit_is_withheld_with_status_2', COMMANDS, ["--data-sensitivity", OVERSIZED, "test task"], INVALID_SENSITIVITY, (run, "screening limit"), True)

    yield ParserRefusalCase('test_argument_past_the_screening_limit_is_withheld_with_status_2', COMMANDS, [f"--unknown={OVERSIZED}", "test task"], UNRECOGNIZED, (run, "screening limit"), True)


class ArgparseScreeningTests(unittest.TestCase):
    """Argument parser errors from both outbound-screened commands never repeat a supplied value."""

    def _scratch(self) -> tuple[Path, Path]:
        scratch = Path(tempfile.mkdtemp(prefix="argparse-screening-"))
        self.addCleanup(_remove_tree, scratch)
        home = scratch / "home"
        home.mkdir()
        return home, scratch / "spy.log"

    def _environment(self, home: Path, spy_log: Path) -> dict[str, str]:
        env = {key: value for key, value in os.environ.items() if key not in {"FORCE_COLOR", "PYTHON_COLORS"}}
        env.update(
            HOME=str(home),
            CWO_AUDIT_FILE=str(home / "audit" / "audit.jsonl"),
            NO_COLOR="1",
            ARGPARSE_TEST_SPY_LOG=str(spy_log),
        )
        return env

    def _run(self, command: list[str], home: Path, spy_log: Path) -> tuple[int, str, str]:
        result = subprocess.run(command, capture_output=True, cwd=ROOT, env=self._environment(home, spy_log), timeout=120)
        return result.returncode, result.stdout.decode("utf-8", "replace"), result.stderr.decode("utf-8", "replace")

    def _modes(self, script: str, args: list[str]) -> list[tuple[str, list[str]]]:
        """The command run directly, and run under the network and audit spies."""
        path = str(SCRIPTS / script)
        return [("direct", [sys.executable, path, *args]), ("spied", [sys.executable, "-c", DRIVER, path, *args])]

    def _assert_no_effects(self, home: Path, spy_log: Path) -> None:
        self.assertEqual(sorted(str(path.relative_to(home)) for path in home.rglob("*")), [], "nothing is written under HOME")
        self.assertFalse(spy_log.exists(), spy_log.read_text(encoding="utf-8") if spy_log.exists() else "")

    def _assert_withheld(self, script: str, args: list[str], expected: str, secrets: tuple[str, ...], *, spied_only: bool = False) -> None:
        modes = self._modes(script, args)
        # The prog name is the basename without extension (e.g., "dispatch_work" not "dispatch_work.py").
        prog = script.removesuffix(".py")
        for mode, command in modes[1:] if spied_only else modes:
            with self.subTest(script=script, mode=mode):
                home, spy_log = self._scratch()
                rc, stdout, stderr = self._run(command, home, spy_log)
                self.assertEqual(rc, 2, stderr[-2000:])
                self.assertEqual(stdout, "", "nothing is written to stdout on an argument error")
                for secret in secrets:
                    self.assertNotIn(secret, stdout)
                    self.assertNotIn(secret, stderr)
                self.assertIn(f"{prog}: error: {expected}\n", stderr)
                self.assertTrue(stderr.startswith("usage: "), stderr[:200])
                self.assertNotIn("Traceback", stderr)
                self._assert_no_effects(home, spy_log)

    def test_argument_error_refusal_rows(self) -> None:
        for row in _parser_refusal_rows():
            with self.subTest(original=row.original, option=row.arguments[0]):
                for script in row.scripts:
                    self._assert_withheld(script, row.arguments, row.diagnostic, row.secrets, spied_only=row.spied_only)


    def test_screening_refusal_while_parsing_exits_2_without_details(self) -> None:
        home, spy_log = self._scratch()
        rc, stdout, stderr = self._run([sys.executable, "-c", REFUSING_TYPE, str(SCRIPTS), "--value", f"password={TOKEN}"], home, spy_log)
        self.assertEqual(rc, 2, stderr[-2000:])
        self.assertEqual(stdout, "")
        for secret in (TOKEN, "REFUSAL-SENTINEL"):
            self.assertNotIn(secret, stderr)
        self.assertIn("refusing_type: error: an argument was refused by the outbound screen (details withheld)\n", stderr)
        self.assertNotIn("Traceback", stderr)
        self._assert_no_effects(home, spy_log)

    def test_credential_shaped_invocation_name_is_never_echoed_on_error(self) -> None:
        # argv[0] is caller-controlled (via wrapper, symlink, or copied name). The program name in
        # usage and error output must derive from the trusted command_name parameter, not argv[0].
        argv0_sentinel = "password=PROBE_SENTINEL.py"
        for script in COMMANDS:
            with self.subTest(script=script):
                home, spy_log = self._scratch()
                # Invoke the script through a credential-shaped name in the test's scratch directory,
                # never in the source tree, which other tests hash while they run.
                # DRIVER adds the resolved script directory to sys.path, as Python does for a symlinked script.
                original = SCRIPTS / script
                renamed = home.parent / argv0_sentinel
                renamed.symlink_to(original)
                prog = script.removesuffix(".py")
                try:
                    # Install spies via the driver, which sets sys.path and imports the spies
                    command = [sys.executable, "-c", DRIVER, str(renamed), "--data-sensitivity", "bogus", "test task"]
                    rc, stdout, stderr = self._run(command, home, spy_log)
                    self.assertEqual(rc, 2, stderr[-2000:])
                    self.assertEqual(stdout, "")
                    self.assertNotIn("PROBE_SENTINEL", stdout)
                    self.assertNotIn("PROBE_SENTINEL", stderr)
                    self.assertNotIn("password=", stderr)
                    self.assertIn(f"{prog}: error: {INVALID_SENSITIVITY}\n", stderr)
                    self.assertTrue(stderr.startswith("usage: "), stderr[:200])
                    self._assert_no_effects(home, spy_log)
                finally:
                    renamed.unlink(missing_ok=True)

    def test_credential_shaped_invocation_name_is_never_echoed_in_help(self) -> None:
        # Help output must use the trusted command_name, not the caller-controlled argv[0].
        argv0_sentinel = "token=PROBE_SENTINEL.py"
        for script in COMMANDS:
            with self.subTest(script=script):
                home, spy_log = self._scratch()
                # Invoke the script through a credential-shaped name in the test's scratch directory,
                # never in the source tree, which other tests hash while they run.
                original = SCRIPTS / script
                renamed = home.parent / argv0_sentinel
                renamed.symlink_to(original)
                try:
                    # Install spies via the driver
                    command = [sys.executable, "-c", DRIVER, str(renamed), "--help"]
                    rc, stdout, stderr = self._run(command, home, spy_log)
                    self.assertEqual(rc, 0, stderr[-2000:])
                    self.assertTrue(stdout.startswith("usage: "), stdout[:200])
                    self.assertNotIn("PROBE_SENTINEL", stdout)
                    self.assertNotIn("PROBE_SENTINEL", stderr)
                    self.assertNotIn("token=", stdout)
                    self.assertIn("--data-sensitivity", stdout)
                    self.assertEqual(stderr, "")
                    self._assert_no_effects(home, spy_log)
                finally:
                    renamed.unlink(missing_ok=True)

    def test_help_still_works(self) -> None:
        for script in COMMANDS:
            for mode, command in self._modes(script, ["--help"]):
                with self.subTest(script=script, mode=mode):
                    home, spy_log = self._scratch()
                    rc, stdout, stderr = self._run(command, home, spy_log)
                    self.assertEqual(rc, 0, stderr[-2000:])
                    self.assertTrue(stdout.startswith("usage: "), stdout[:200])
                    self.assertIn("--data-sensitivity", stdout)
                    self.assertEqual(stderr, "")
                    self._assert_no_effects(home, spy_log)


def _remove_tree(path: Path) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
