"""Fake-only regressions; importing this module never launches a binary."""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import json.scanner
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "tools" / "check_protocol_startup_fixture.py"
SPEC = importlib.util.spec_from_file_location("w14_startup_fixture_under_test", SOURCE)
fixture = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = fixture
SPEC.loader.exec_module(fixture)
SUCCESS = {
    "appServerVersion": "0.164.0",
    "configRequirements": {"supportsIndependentSpeedModes": True, "requirements": None},
}
DETAILS = (
    "default_permissions refers to undefined profile `cwo-unknown-name`",
    "config defines `[permissions]` profiles but does not set `default_permissions`",
    "permissions profile `cwo-offline-deny` extends undefined profile `cwo-missing-parent`",
    "permissions profile inheritance cycle detected: "
    "cwo-offline-deny -> cwo-second -> cwo-offline-deny",
)
HASHES = (
    "2a8a3ad90bb351fde158d29ebf69909a83c24cc3783a8874b3f74516310ad62d",
    "b77926322e65419922964f1f23768f66a8632d0a7b59951ac9d62dada0801f1e",
    "06282633caaa297184332f5594b58b0a59af766161012bfb18c851e0ff954318",
    "61fc76abf76f000dbf2dd2ce3fcda0e7a2d8fb0d9c06cbce06266c44c3c6ae53",
    "f7c45495f84eb32efa29141267168ecc52d6cf428e069890dba00626f60b90fd",
    "73dc4f5bb43402f7132103c905f6260c6aa2d645551c63857091e3f992d49866",
    "fb54ae764ed11954be9ee9a7fe337cd736361c1bbfc5528d91fe7e2ee8dd91e7",
)


def encoded(payload):
    return (json.dumps(payload) + "\n").encode("utf-8")


def failure_payload(detail):
    return {
        "error": {
            "code": -32600,
            "data": {
                "reason": "configLoad", "filePath": None, "line": None, "column": None,
                "detail": detail,
            },
            "message": "failed to load configuration: " + detail,
        }
    }


def response(index, command, config):
    if index < 2:
        return subprocess.CompletedProcess(command, 0, encoded(SUCCESS), b"")
    if index == 6:
        detail = f"{config}:2:1: unknown configuration field `this_is_not_a_known_config_field`"
        payload = failure_payload(detail)
        payload["error"]["data"].update(filePath=str(config), line=2, column=1)
    else:
        payload = failure_payload(DETAILS[index - 2])
    return subprocess.CompletedProcess(
        command, 1, encoded(payload), b"Error: startup configuration unavailable\n"
    )


@contextlib.contextmanager
def recorded_lifecycle(fail_cleanup=False):
    """Snapshot real observations before attempting real temporary cleanup."""
    original_temp = tempfile.TemporaryDirectory
    original_observe = fixture._observe_private
    events, snapshots = [], []

    def observe(record, root, config, configuration):
        original_observe(record, root, config, configuration)
        snapshots.append(copy.deepcopy(record))
        events.append(("observed", str(root)))

    class RecordingTemp(original_temp):
        def __exit__(self, *args):
            events.append(("cleanup", self.name))
            result = super().__exit__(*args)
            if fail_cleanup:
                raise OSError("unit-only cleanup failure after real cleanup")
            return result

    with (
        mock.patch.object(fixture, "_observe_private", side_effect=observe),
        mock.patch.object(fixture.tempfile, "TemporaryDirectory", RecordingTemp),
    ):
        yield events, snapshots


class StartupFixtureTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.outer = Path(temp.name)
        self.binary = self.outer / "unit-only-binary"
        content = b"unit-only fake binary, never executed\n"
        self.binary.write_bytes(content)
        # Pin replacement and /tmp staging are confined to these fake unit tests.
        pins = mock.patch.multiple(
            fixture, BINARY_SIZE=len(content), BINARY_SHA256=hashlib.sha256(content).hexdigest()
        )
        pins.start()
        self.addCleanup(pins.stop)
        home = mock.patch.object(fixture.Path, "home", return_value=self.outer)
        home.start()
        self.addCleanup(home.stop)
        real_run = mock.patch.object(
            fixture.subprocess, "run", side_effect=AssertionError("real subprocess forbidden in fake units")
        )
        real_run.start()
        self.addCleanup(real_run.stop)
        self.calls = []

    def fake_runner(self, command, **kwargs):
        config = Path(kwargs["env"]["CODEX_HOME"]) / "config.toml"
        self.assertTrue(config.is_file())
        self.assertTrue(Path(kwargs["cwd"]).is_dir())
        index = len(self.calls)
        self.calls.append((command, kwargs, config.read_bytes(), config.parent.parent))
        return response(index, command, config)

    def run_fake(self, runner=None):
        return fixture.run_fixture(self.binary, runner=self.fake_runner if runner is None else runner)

    def assert_cleaned(self):
        for _, _, _, root in self.calls:
            self.assertFalse(root.exists())

    def test_all_seven_frozen_outcomes_and_configuration_hashes(self):
        report = self.run_fake()
        self.assertTrue(report["passed"], report)
        self.assertEqual(report["case_count"], 7)
        self.assertEqual(report["completed_case_count"], 7)
        self.assertEqual(report["passed_case_count"], 7)
        self.assertEqual(report["binary_before"], report["binary_after"])
        self.assertEqual([case["config_sha256"] for case in report["cases"]], list(HASHES))
        self.assertEqual(
            [case["classification"] for case in report["cases"]],
            ["healthy", "healthy"] + ["expected-config-refusal"] * 5,
        )
        self.assertEqual(
            [case["name"] for case in report["cases"]],
            [
                "known-builtin", "named-root-deny", "unknown-named-with-valid-catalog",
                "missing-default-with-valid-catalog", "undefined-parent", "cycle-parent",
                "strict-unknown-field",
            ],
        )
        self.assertEqual(
            [hashlib.sha256(call[2]).hexdigest() for call in self.calls], list(HASHES)
        )
        self.assert_cleaned()

    def test_fixed_argv_private_directories_and_environment(self):
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "unit-sentinel", "HTTPS_PROXY": "unit-sentinel"}):
            report = self.run_fake()
        self.assertTrue(report["passed"], report)
        roots = []
        for command, kwargs, configuration, root in self.calls:
            self.assertEqual(command, [
                str(self.binary), "-m", "gpt-6.1-sol", "-c", 'service_tier="default"',
                "-c", 'model_reasoning_effort="high"',
                "app-server", "--strict-config", "--print-startup-config",
            ])
            self.assertEqual(set(kwargs), {"cwd", "env", "stdin", "capture_output", "shell", "timeout"})
            self.assertEqual(
                kwargs["env"],
                {"HOME": str(root / "home"), "CODEX_HOME": str(root / "home"),
                 "PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
            self.assertEqual(kwargs["cwd"], str(root / "work"))
            self.assertIs(kwargs["shell"], False)
            self.assertIs(kwargs["capture_output"], True)
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(kwargs["timeout"], 15)
            self.assertEqual(root.parent, self.outer)
            self.assertTrue(configuration)
            roots.append(root)
        self.assertEqual(len(set(roots)), 7)
        self.assert_cleaned()

    def test_result_and_private_effect_observation_precede_cleanup(self):
        original = fixture._classify
        checked = []
        def classify(case, result, config):
            self.assertTrue(config.exists())
            checked.append(config.parent.parent)
            return original(case, result, config)
        def runner(command, **kwargs):
            home = Path(kwargs["env"]["HOME"])
            (home / "unit-marker").write_text("ephemeral", encoding="utf-8")
            return self.fake_runner(command, **kwargs)
        with mock.patch.object(fixture, "_classify", side_effect=classify):
            report = self.run_fake(runner)
        self.assertTrue(report["passed"], report)
        self.assertEqual(len(checked), 7)
        for case in report["cases"]:
            self.assertIn(
                {"path": "home/unit-marker", "kind": "file"}, case["private_after"]["entries"]
            )
            self.assertEqual(case["config_after"]["sha256"], case["config_sha256"])
        self.assert_cleaned()

    def _deep_json_cli(self, python_scanner=False):
        raw = ("[" * 10000 + "0" + "]" * 10000).encode("utf-8")
        output = io.StringIO()
        parser_recursed = False

        def runner(command, **kwargs):
            self.fake_runner(command, **kwargs)
            home = Path(kwargs["env"]["HOME"])
            (home / "unit-marker").write_text("ephemeral", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, raw, b"")

        with recorded_lifecycle() as (events, snapshots):
            with contextlib.ExitStack() as patches:
                if python_scanner:
                    patches.enter_context(
                        mock.patch.object(
                            json.scanner, "make_scanner", json.scanner.py_make_scanner
                        )
                    )
                try:
                    json.loads(
                        raw, object_pairs_hook=fixture._unique_object, parse_constant=fixture._reject_constant
                    )
                except RecursionError:
                    parser_recursed = True
                patches.enter_context(mock.patch.object(fixture.subprocess, "run", side_effect=runner))
                with contextlib.redirect_stdout(output):
                    status = fixture.main(["--binary", str(self.binary), "--json"])
        return raw, parser_recursed, status, output.getvalue(), events, snapshots

    def _assert_lifecycle_evidence(self, report, events, snapshots):
        self.assertEqual(len(report["cases"]), 7)
        self.assertEqual(len(snapshots), 7)
        for index, (record, snapshot) in enumerate(zip(report["cases"], snapshots, strict=True)):
            for key in (
                "stdout", "stderr", "returncode", "classification",
                "private_after", "config_after",
            ):
                self.assertEqual(record[key], snapshot[key])
            self.assertEqual(
                events[index * 2:index * 2 + 2],
                [("observed", record["fixture_root"]), ("cleanup", record["fixture_root"])],
            )
            self.assertIn(
                {"path": "home/unit-marker", "kind": "file"}, record["private_after"]["entries"]
            )
            self.assertEqual(record["config_after"]["sha256"], record["config_sha256"])
        self.assertEqual(len(events), 14)

    def _assert_deep_json_failure(self, result):
        raw, parser_recursed, status, text, events, snapshots = result
        self.assertLess(len(raw), fixture.OUTPUT_LIMIT)
        self.assertEqual(status, 1)
        report = json.loads(text)
        self.assertFalse(report["passed"])
        self.assertEqual(report["completed_case_count"], 7)
        self.assertEqual(report["passed_case_count"], 0)
        self._assert_lifecycle_evidence(report, events, snapshots)
        for record in report["cases"]:
            self.assertFalse(record["passed"])
            self.assertEqual(record["returncode"], 0)
            self.assertEqual(record["classification"], "unexpected")
            self.assertEqual(record["stdout"]["text"], raw.decode("utf-8"))
            self.assertEqual(record["stdout"]["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(record["stdout"]["bytes"], 20001)
            self.assertFalse(record["stdout"]["truncated"])
            self.assertEqual(record["stderr"]["text"], "")
            self.assertTrue(any(issue.startswith("invalid result: ") for issue in record["issues"]))
        return parser_recursed, report

    def test_default_native_deep_json_retains_structured_failure(self):
        recursed, report = self._assert_deep_json_failure(self._deep_json_cli())
        if sys.version_info[:2] == (3, 12) and json.scanner.c_make_scanner is not None:
            self.assertTrue(recursed, "the native 3.12 regression must reach parser recursion")
        if not recursed:
            self.assertIn("success must be an object", report["cases"][0]["issues"][0])

    def test_real_stdlib_python_scanner_recursion_retains_structured_failure(self):
        parser_recursed, _ = self._assert_deep_json_failure(self._deep_json_cli(python_scanner=True))
        self.assertTrue(parser_recursed, "the real stdlib Python scanner must reach recursion")

    def test_cleanup_oserror_retains_case_output_and_observations(self):
        output = io.StringIO()

        def runner(command, **kwargs):
            index = len(self.calls)
            result = self.fake_runner(command, **kwargs)
            home = Path(kwargs["env"]["HOME"])
            (home / "unit-marker").write_text("ephemeral", encoding="utf-8")
            if index == 0:
                result.stdout = b"{"
                result.stderr = b"primary diagnostic\n"
            return result

        with (
            recorded_lifecycle(fail_cleanup=True) as (events, snapshots),
            mock.patch.object(fixture.subprocess, "run", side_effect=runner),
            contextlib.redirect_stdout(output),
        ):
            status = fixture.main(["--binary", str(self.binary), "--json"])
        report = json.loads(output.getvalue())
        self.assertEqual(status, 1)
        self.assertFalse(report["passed"])
        self.assertEqual(report["completed_case_count"], 7)
        self.assertEqual(report["passed_case_count"], 0)
        self._assert_lifecycle_evidence(report, events, snapshots)
        self.assertTrue(report["cases"][0]["issues"][0].startswith("invalid result: "))
        for record, snapshot in zip(report["cases"], snapshots, strict=True):
            self.assertFalse(record["passed"])
            self.assertEqual(record["issues"][:-1], snapshot["issues"])
            self.assertEqual(
                record["issues"][-1],
                "fixture cleanup failed: unit-only cleanup failure after real cleanup",
            )
        self.assertEqual(report["cases"][0]["stdout"]["text"], "{")
        self.assertEqual(report["cases"][0]["stderr"]["text"], "primary diagnostic\n")
        self.assert_cleaned()

    def test_unexpected_results_are_structured_failures(self):
        bad_version = dict(SUCCESS, appServerVersion="0.163.0")
        bad_requirements = dict(SUCCESS, configRequirements={})
        bad_speed = dict(SUCCESS, configRequirements={"supportsIndependentSpeedModes": 1, "requirements": None})
        negative = failure_payload(DETAILS[0])
        boolean_code = failure_payload(DETAILS[0])
        boolean_code["error"]["code"] = False
        wrong_reason = failure_payload(DETAILS[0])
        wrong_reason["error"]["data"]["reason"] = "unrelated"
        both = dict(SUCCESS, error=negative["error"])
        duplicate = (
            b'{"appServerVersion":"0.164.0","appServerVersion":"0.164.0",'
            b'"configRequirements":{"supportsIndependentSpeedModes":true,"requirements":null}}\n'
        )
        mutations = [
            ("bad-json", 0, {"stdout": b"{"}),
            ("wrong-version", 0, {"stdout": encoded(bad_version)}),
            ("missing-fields", 0, {"stdout": b'{"appServerVersion":"0.164.0"}'}),
            ("bad-requirements", 0, {"stdout": encoded(bad_requirements)}),
            ("bool-vs-int", 0, {"stdout": encoded(bad_speed)}),
            ("warning", 0, {"stderr": b"WARNING: alias problem\n"}),
            ("ansi", 0, {"stdout": b"\x1b[0m" + encoded(SUCCESS)}),
            ("boolean-success-exit", 0, {"returncode": False}),
            ("boolean-failure-exit", 2, {"returncode": True}),
            ("general-nonzero", 2, {"returncode": 7}),
            ("boolean-error-code", 2, {"stdout": encoded(boolean_code)}),
            ("duplicate", 0, {"stdout": duplicate}),
            ("error-plus-success", 0, {"stdout": encoded(both)}),
            ("error-plus-success-negative", 2, {"stdout": encoded(both)}),
            ("wrong-case", 3, {"stdout": encoded(negative)}),
            ("wrong-reason", 2, {"stdout": encoded(wrong_reason)}),
            ("negative-warning", 2, {"stderr": b"WARNING\nError: startup configuration unavailable\n"}),
            ("missing-negative-stderr", 2, {"stderr": b""}),
            ("bad-utf8", 0, {"stdout": b"\xff"}),
            ("non-json-constant", 0, {"stdout": b'{"appServerVersion":NaN}'}),
            ("non-object", 0, {"stdout": b"[]"}),
            ("oversize", 0, {"stdout": b"x" * (fixture.OUTPUT_LIMIT + 1)}),
        ]
        for name, target, changes in mutations:
            with self.subTest(name=name):
                self.calls = []
                def runner(command, **kwargs):
                    index = len(self.calls)
                    result = self.fake_runner(command, **kwargs)
                    if index == target:
                        for field, value in changes.items():
                            setattr(result, field, value)
                    return result
                report = self.run_fake(runner)
                self.assertFalse(report["passed"])
                self.assertFalse(report["cases"][target]["passed"])
                self.assertTrue(report["cases"][target]["issues"])
                self.assertEqual(report["completed_case_count"], 7)
                json.dumps(report)
                self.assert_cleaned()

    def test_negative_shape_locations_and_details_are_not_generic(self):
        for index in range(2, 7):
            with self.subTest(case=index):
                config = self.outer / "home" / "config.toml"
                result = response(index, [], config)
                payload = json.loads(result.stdout)
                payload["error"]["data"]["detail"] = "some unrelated load error"
                result.stdout = encoded(payload)
                with self.assertRaises(ValueError):
                    fixture._classify(fixture.CASES[index], result, config)
        strict = response(6, [], self.outer / "config.toml")
        payload = json.loads(strict.stdout)
        payload["error"]["data"]["line"] = True
        strict.stdout = encoded(payload)
        with self.assertRaises(ValueError):
            fixture._classify(fixture.CASES[6], strict, self.outer / "config.toml")

    def test_timeout_and_oserror_keep_partial_output_and_cleanup(self):
        for failure in ("timeout", "oserror"):
            with self.subTest(failure=failure):
                self.calls = []
                def runner(command, **kwargs):
                    self.fake_runner(command, **kwargs)
                    if failure == "timeout":
                        raise subprocess.TimeoutExpired(command, 15, output=b"partial", stderr=b"warning")
                    raise OSError("unit-only launch refusal")
                report = self.run_fake(runner)
                self.assertFalse(report["passed"])
                self.assertEqual(len(self.calls), 7)
                self.assertTrue(all(case["issues"] for case in report["cases"]))
                if failure == "timeout":
                    self.assertEqual(report["cases"][0]["stdout"]["text"], "partial")
                    self.assertEqual(report["cases"][0]["stderr"]["text"], "warning")
                self.assert_cleaned()

    def test_missing_wrong_and_symlink_artifacts_never_invoke_runner(self):
        wrong_size = self.outer / "wrong-size"
        wrong_size.write_bytes(b"x")
        wrong_hash = self.outer / "wrong-hash"
        wrong_hash.write_bytes(b"x" * fixture.BINARY_SIZE)
        symlink = self.outer / "binary-link"
        symlink.symlink_to(self.binary)
        for path in (self.outer / "missing", self.outer, wrong_size, wrong_hash, symlink):
            with self.subTest(path=path):
                runner = mock.Mock()
                report = fixture.run_fixture(path, runner=runner)
                self.assertFalse(report["passed"])
                self.assertTrue(report["issues"])
                self.assertEqual(report["cases"], [])
                runner.assert_not_called()

    def test_binary_and_configuration_changes_are_reported(self):
        def binary_mutator(command, **kwargs):
            result = self.fake_runner(command, **kwargs)
            self.binary.write_bytes(b"x" * fixture.BINARY_SIZE)
            return result
        report = self.run_fake(binary_mutator)
        self.assertFalse(report["passed"])
        self.assertNotEqual(report["binary_before"], report["binary_after"])
        self.assertTrue(report["issues"])
        self.assert_cleaned()
        # Restore the unit-only artifact before the second independent run.
        content = b"unit-only fake binary, never executed\n"
        self.binary.write_bytes(content)
        self.calls = []
        def config_mutator(command, **kwargs):
            result = self.fake_runner(command, **kwargs)
            config = Path(kwargs["env"]["HOME"]) / "config.toml"
            config.write_bytes(b"x" * config.stat().st_size)
            return result
        report = self.run_fake(config_mutator)
        self.assertFalse(report["passed"])
        self.assertTrue(all(case["issues"] for case in report["cases"]))
        self.assert_cleaned()

    def test_cli_requires_explicit_binary_and_json_preserves_failure(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output), self.assertRaises(SystemExit) as caught:
            fixture.main(["--json"])
        self.assertEqual(caught.exception.code, 2)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = fixture.main(["--binary", str(self.outer / "missing"), "--json"])
        self.assertEqual(status, 1)
        self.assertFalse(json.loads(output.getvalue())["passed"])
        with mock.patch.object(fixture.subprocess, "run", side_effect=self.fake_runner):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = fixture.main(["--binary", str(self.binary), "--json"])
        self.assertEqual(status, 0)
        self.assertTrue(json.loads(output.getvalue())["passed"])
        self.assert_cleaned()


class PublicPinTests(unittest.TestCase):
    def test_public_pin_remains_fixture_specific(self):
        self.assertEqual(fixture.BINARY_SIZE, 308139304)
        self.assertEqual(
            fixture.BINARY_SHA256,
            "b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306",
        )


if __name__ == "__main__":
    unittest.main()
