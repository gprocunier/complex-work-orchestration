"""Bounded installed checked-command consumer evidence in disposable directories."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

from tests.installed_consumer_fixtures import RestoredInstalledRows
from tests import test_install_projection as fixture
from tests.test_installed_numeric_rollback import MV_SHIM


RECORD = ".cwo-install-manifest.json"
DEPTH = 10000


PROBE = r'''
import contextlib
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from unittest.mock import patch

root, checkout, source, area = (Path(value).resolve() for value in sys.argv[1:5])
context_record = json.load(sys.stdin)
scripts, inputs, outputs = root / "scripts", area / "inputs", area / "outputs"
library = Path(os.__file__).resolve().parent
assert sys.flags.isolated and sys.dont_write_bytecode
assert root == area / "skills" / "complex-work-orchestration"
assert source == area / "source" and not source.exists()
assert not area.is_relative_to(checkout)
assert Path.cwd() == area / "home" == Path(os.environ["HOME"]).resolve()
assert all(not Path(item).resolve().is_relative_to(checkout) for item in sys.path)
assert all(not Path(item).resolve().is_relative_to(source) for item in sys.path)
assert not any(name == "cwo_core" or name.startswith("cwo_core.") for name in sys.modules)
sys.path.insert(0, str(scripts))
reads = {"installed": [], "input": [], "output": [], "library": []}
writes, mutations, denied, actions = [], [], [], []
descriptors = {}
real_open = os.open

def path_for(value, directory=None):
    if isinstance(value, int):
        return descriptors.get(value)
    path = Path(os.fsdecode(value))
    if directory not in (None, -1) and not path.is_absolute():
        path = descriptors[directory] / path
    return path.resolve()

def block(kind):
    denied.append(kind)
    raise RuntimeError("EXAMPLE effect refused")

def action(kind):
    actions.append(kind)
    block(kind)

def read_path(path):
    if path is None:
        return
    for label, directory in (("installed", root), ("input", inputs),
                             ("output", outputs), ("library", library)):
        if path.is_relative_to(directory):
            reads[label].append(str(path))
            return
    block("read")

def write_path(path):
    if path is None or not path.is_relative_to(outputs):
        block("write")
    writes.append(str(path))

def mutation(event, args):
    if event in {"os.rename", "os.link"}:
        paths = [path_for(args[0], args[2]), path_for(args[1], args[3])]
    elif event == "os.symlink":
        block("symlink")
    else:
        paths = [path_for(args[0])]
    for path in paths:
        write_path(path)
    mutations.append(event)

def audit(event, args):
    if event == "open":
        if isinstance(args[0], int):
            return
        path = path_for(args[0])
        flags = args[2] or 0
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            write_path(path)
        else:
            read_path(path)
    elif event in {"os.listdir", "os.scandir"}:
        read_path(path_for(args[0]))
    elif event in {"os.remove", "os.rmdir", "os.mkdir", "os.rename", "os.link",
                   "os.symlink", "os.chmod", "os.chown", "os.truncate", "os.utime"}:
        mutation(event, args)
    elif event in {"subprocess.Popen", "os.system", "os.exec", "os.spawn",
                   "os.posix_spawn", "os.fork", "os.forkpty"}:
        block("process")
    elif event.startswith("socket."):
        block("socket")

def open_path(path, flags, *args, **kwargs):
    directory = kwargs.pop("dir_fd", None)
    resolved = path_for(path, directory)
    descriptor = real_open(resolved, flags, *args, **kwargs)
    descriptors[descriptor] = resolved
    return descriptor

# Record effects before installed imports and every consumer call.
sys.addaudithook(audit)

def command(version=1):
    return {
        "spec_type": "cwo-checked-command-spec", "version": version,
        "command_id": "EXAMPLE_COMMAND", "mode": "argv", "argv": ["EXAMPLE_NEVER_RUN"],
        "cwd": str(area / "home"), "env": {}, "inherit_environment": False,
        "stdin": None, "source": None, "preflights": [], "mutation_intent": "none",
        "allowed_paths": [], "timeout_seconds": 1,
    }

def sequence(version=1, item=None):
    return {
        "spec_type": "cwo-checked-command-sequence-spec", "version": version,
        "sequence_id": "EXAMPLE_SEQUENCE", "packet_id": "EXAMPLE_PACKET",
        "work_plan_sha256": hashlib.sha256(b"EXAMPLE_WORK_PLAN").hexdigest(), "workdir": str(area / "home"),
        "commands": [command() if item is None else item],
    }

def value_error(call):
    try:
        call()
    except ValueError:
        return
    raise AssertionError("Expected input refusal")

def command_refusal(result):
    assert result["result_type"] == "cwo-checked-command-result"
    assert result["preflight_status"] == "failed"
    assert result["failure_class"] == "command-construction-failed"
    assert result["execution_status"] == "not-started"
    assert result["execution_started"] is False and result["mutation_started"] is False
    assert result["mutated_paths"] == [] and result["exit_code"] is None
    assert result["quarantine_required"] is False
    assert result["diagnostics"]["stderr"]

def sequence_refusal(result):
    assert result["result_type"] == "cwo-checked-command-sequence-result"
    assert result["status"] == "blocked" and result["execution_started"] is False
    assert result["failure_class"] == "invalid-sequence-spec"
    assert result["completed_count"] == 0 and result["command_results"] == []

def normalize_cases(cc, seq):
    for version in (1, 1.0):
        normalized = cc.normalize_command_spec(command(version))
        assert type(normalized["version"]) is int and normalized["version"] == 1
        normalized = seq.normalize_sequence_spec(sequence(version, command(version)))
        assert type(normalized["version"]) is int and normalized["version"] == 1
        assert type(normalized["commands"][0]["version"]) is int
        assert normalized["commands"][0]["version"] == 1

def boolean_cases(cc, seq):
    with patch.object(seq, "execute_checked_command", wraps=cc.execute_checked_command) as calls:
        for version in (True, False):
            value_error(lambda: cc.normalize_command_spec(command(version)))
            command_refusal(cc.execute_checked_command(command(version)))
            for spec in (sequence(version), sequence(item=command(version))):
                value_error(lambda: seq.normalize_sequence_spec(spec))
                sequence_refusal(seq.execute_checked_command_sequence(spec))
        assert calls.call_count == 0

def native_cases(cc, seq, text):
    try:
        native = json.loads(text)
    except RecursionError:
        outcome = "recursion-refused"
    else:
        assert isinstance(native, list)
        outcome = "list-parsed"
    if sys.version_info[:2] == (3, 12):
        assert outcome == "recursion-refused"
    if sys.version_info[:2] == (3, 14):
        assert outcome == "list-parsed"
    pattern = "(" * 2000 + "EXAMPLE" + ")" * 2000
    try:
        re.compile(pattern)
    except RecursionError:
        pass
    else:
        raise AssertionError("Expected native regex recursion")
    cases = [("regex", pattern), ("json-policy", text)]
    if outcome == "recursion-refused":
        cases.append(("json", text))
    with patch.object(seq, "execute_checked_command", wraps=cc.execute_checked_command) as calls:
        for kind, value in cases:
            spec = command()
            spec["preflights"] = [{"kind": kind, "value": value}]
            result = cc.execute_checked_command(spec)
            command_refusal(result)
            assert result["linter"] == "nested-language"
            if kind == "json-policy" and outcome == "list-parsed":
                assert result["diagnostics"]["stderr"] == "json-policy preflight requires an object"
            terminal = seq.execute_checked_command_sequence(sequence(item=spec))
            assert terminal["status"] == "blocked" and terminal["completed_count"] == 0
            assert terminal["failed_command_id"] == "EXAMPLE_COMMAND"
            assert len(terminal["command_results"]) == 1
            assert terminal["command_results"][0]["execution_started"] is False
        assert calls.call_count == len(cases)
    return outcome

def integer_cases(cc, seq, texts):
    assert sys.get_int_max_str_digits() == 4300
    assert sys._xoptions.get("int_max_str_digits") == "4300"
    input_text = texts["EXAMPLE_integer_at_limit"]
    assert len(input_text) == 4300
    parsed = json.loads(input_text)
    assert type(parsed) is int
    value_error(lambda: cc.normalize_command_spec(parsed))
    value_error(lambda: seq.normalize_sequence_spec(parsed))
    result = cc.execute_checked_command(parsed)
    command_refusal(result)
    assert result["diagnostics"]["stderr"] == "spec must be a mapping"
    with patch.object(seq, "execute_checked_command", wraps=cc.execute_checked_command) as calls:
        sequence_refusal(seq.execute_checked_command_sequence(parsed))
        assert calls.call_count == 0
    input_text = texts["EXAMPLE_integer_over_limit"]
    assert len(input_text) == 4301
    try:
        json.loads(input_text)
    except ValueError as error:
        assert type(error) is ValueError
    else:
        raise AssertionError("Expected native integer conversion refusal")
    return {"at_limit": "integer-parsed", "over_limit": "conversion-refused"}

def cli_case(module, path, output, state):
    argv = [module.__name__, str(path)]
    if output is not None:
        argv += ["--output", str(output)]
    if state is not None:
        argv += ["--state", str(state)]
    out, err, code = io.StringIO(), io.StringIO(), None
    with patch.object(sys, "argv", argv), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            module.main()
        except SystemExit as error:
            code = error.code
    assert code == 2 and err.getvalue() == ""
    if output is None:
        result = json.loads(out.getvalue())
    else:
        assert out.getvalue() == ""
        result = json.loads(output.read_text(encoding="utf-8"))
    if state is None:
        command_refusal(result)
    else:
        sequence_refusal(result)
        assert json.loads(state.read_text(encoding="utf-8")) == result

def cli_cases(command_cli, sequence_cli):
    count = 0
    for name in ("syntax", "deep", "EXAMPLE_integer_at_limit", "EXAMPLE_integer_over_limit"):
        path = Path(context_record["inputs"][name]["path"])
        for label, module in (("command", command_cli), ("sequence", sequence_cli)):
            for file_output in (False, True):
                stem = f"EXAMPLE_{label}_{name}_{int(file_output)}"
                output = outputs / (stem + ".json") if file_output else None
                state = outputs / (stem + ".state.json") if label == "sequence" else None
                cli_case(module, path, output, state)
                count += 1
    return count

def bindings():
    found = []
    for name, module in list(sys.modules.items()):
        if not (name == "cwo_core" or name.startswith("cwo_core.") or
                name in {"run_checked_command", "run_checked_command_sequence", "check_installed_skill"}):
            continue
        relative = "cwo_core/__init__.py" if name == "cwo_core" else name.replace(".", "/") + ".py"
        expected = scripts / relative
        assert Path(module.__file__).resolve() == expected
        assert Path(module.__spec__.origin).resolve() == expected
        if hasattr(module, "__path__"):
            assert [Path(item).resolve() for item in module.__path__] == [expected.parent]
            assert [Path(item).resolve() for item in module.__spec__.submodule_search_locations] == [expected.parent]
        assert str(expected) in reads["installed"]
        found.append(name)
    assert {"cwo_core.checked_command", "cwo_core.checked_command_sequence",
            "run_checked_command", "run_checked_command_sequence", "check_installed_skill"} <= set(found)
    assert "tests" not in sys.modules
    return len(found)

def control(call):
    before = len(denied)
    try:
        call()
    except RuntimeError:
        pass
    else:
        raise AssertionError("Expected effect guard refusal")
    assert len(denied) == before + 1

failure, phase, native, cli_count, origins = None, "imports", None, 0, 0
failure_frames, native_integer = [], None
cc = None
with contextlib.ExitStack() as stack:
    stack.enter_context(patch("os.open", open_path))
    stack.enter_context(patch("tempfile.TemporaryDirectory", side_effect=lambda *a, **k: action("temporary")))
    stack.enter_context(patch("subprocess.run", side_effect=lambda *a, **k: action("run")))
    stack.enter_context(patch("subprocess.Popen", side_effect=lambda *a, **k: action("Popen")))
    try:
        cc = importlib.import_module("cwo_core.checked_command")
        seq = importlib.import_module("cwo_core.checked_command_sequence")
        command_cli = importlib.import_module("run_checked_command")
        sequence_cli = importlib.import_module("run_checked_command_sequence")
        checker = importlib.import_module("check_installed_skill")
        stack.enter_context(patch.object(cc, "_snapshot", side_effect=lambda *a, **k: action("snapshot")))
        phase = "manifest"
        assert checker.REPO_ROOT == root
        assert checker.build_manifest(root) == context_record["manifest"]
        record = json.loads((root / ".cwo-install-manifest.json").read_text(encoding="utf-8"))
        assert record["source_dir"] == str(source)
        assert record["projection"] == context_record["manifest"]["projection"]
        for key in ("source_content_sha256", "installed_content_sha256"):
            assert record[key] == context_record["manifest"]["content_sha256"]
        texts = {}
        for name, item in context_record["inputs"].items():
            path = Path(item["path"])
            assert path.parent == inputs
            raw = path.read_bytes()
            assert hashlib.sha256(raw).hexdigest() == item["sha256"]
            texts[name] = raw.decode("utf-8")
        phase = "normalizers"
        normalize_cases(cc, seq)
        phase = "refusals"
        boolean_cases(cc, seq)
        native = native_cases(cc, seq, texts["deep"])
        phase = "native-integer"
        native_integer = integer_cases(cc, seq, texts)
        assert not writes and not mutations and not denied and not actions
        phase = "cli"
        cli_count = cli_cases(command_cli, sequence_cli)
        phase = "origins"
        origins = bindings()
        assert writes and mutations
        assert all(item["path"] in reads["input"] for item in context_record["inputs"].values())
    except BaseException as error:
        failure = type(error).__name__
        frame = error.__traceback__
        while frame is not None:
            failure_frames.append({
                "filename": frame.tb_frame.f_code.co_filename,
                "function": frame.tb_frame.f_code.co_name,
                "line": frame.tb_lineno,
            })
            frame = frame.tb_next
    observed, action_count = len(denied), len(actions)
    controls = [
        lambda: tempfile.TemporaryDirectory(),
        lambda: subprocess.run(["EXAMPLE_NEVER_RUN"]),
        lambda: subprocess.Popen(["EXAMPLE_NEVER_RUN"]),
        lambda: sys.audit("subprocess.Popen", None, None, None, None),
        lambda: importlib.import_module("socket").socket(),
        lambda: open(checkout / "EXAMPLE_BLOCKED", "rb"),
        lambda: open(source / "EXAMPLE_BLOCKED", "rb"),
        lambda: open(inputs / "EXAMPLE_BLOCKED", "w"),
        lambda: open(root / "EXAMPLE_BLOCKED", "w"),
        lambda: os.mkdir(area / "EXAMPLE_BLOCKED"),
    ]
    if cc is not None:
        controls.append(lambda: cc._snapshot(area))
    for call in controls:
        control(call)
report = {
    "ok": failure is None, "failure": failure, "phase": phase,
    "failure_frames": failure_frames,
    "forbidden": observed, "actions": action_count, "controls": len(controls),
    "reads": {name: len(paths) for name, paths in reads.items()},
    "writes": len(writes), "mutations": len(mutations), "origins": origins,
    "cli_cases": cli_count, "native_json": native, "interpreter": list(sys.version_info[:2]),
    "native_integer": native_integer,
    "int_max_str_digits": sys.get_int_max_str_digits(),
    "int_max_str_digits_option": sys._xoptions.get("int_max_str_digits"),
}
print(json.dumps(report, sort_keys=True))
raise SystemExit(0 if failure is None and observed == 0 and action_count == 0 else 1)
'''


class InstalledCheckedConsumerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.install = fixture.InstallerProjectionTests(
            "test_fresh_install_is_the_projection_and_its_resources_are_usable"
        )
        self.addCleanup(self._cleanup_install)
        self.install.setUp()
        self.assertFalse(self.install.tmp.resolve().is_relative_to(fixture.ROOT.resolve()))
        self.source = self.install.copy_source()
        self.env = {
            **os.environ, "HOME": str(self.install.tmp / "home"),
            "CODEX_HOME": str(self.install.tmp / "home/.codex"),
            "CODEX_SKILLS_DIR": str(self.install.skills),
            "SKILL_VALIDATOR": str(self.install.tmp / "EXAMPLE_no_validator.py"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PATH": str(self.install.shims) + os.pathsep + os.environ.get("PATH", os.defpath),
        }
        for key in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "BASH_ENV", "ENV"):
            self.env.pop(key, None)
        (self.install.tmp / "outputs").mkdir()
        directory = self.install.tmp / "inputs"
        directory.mkdir()
        self.inputs = {}
        for name, text in (
            ("syntax", "{EXAMPLE"),
            ("deep", "[" * DEPTH + "0" + "]" * DEPTH),
            ("EXAMPLE_integer_at_limit", "1" * 4300),
            ("EXAMPLE_integer_over_limit", "1" * 4301),
        ):
            path = directory / (name + ".json")
            raw = text.encode("utf-8")
            path.write_bytes(raw)
            self.inputs[name] = {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}
        self.expected = fixture.checker.build_manifest(self.source)
        self._assert_resources()
        self.real_install()

    def _cleanup_install(self) -> None:
        temporary = getattr(self.install, "_tmp", None)
        try:
            self.install.doCleanups()
        finally:
            if temporary is not None:
                temporary.cleanup()

    def _assert_resources(self) -> None:
        paths = {item["path"] for item in self.expected["files"]}
        required = {
            "SECURITY.md", "policy/install-projection.yaml",
            "schemas/checked-command-spec.schema.json", "schemas/checked-command-result.schema.json",
            "schemas/checked-command-sequence-spec.schema.json",
            "schemas/checked-command-sequence-result.schema.json",
        }
        self.assertLessEqual(required, paths)
        for prefix in ("policy/", "schemas/"):
            self.assertTrue(any(path.startswith(prefix) for path in paths))

    def run_install(self, **extra_env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(self.source / "scripts/install.sh"), "--skills-dir", str(self.install.skills), "--yes"],
            cwd=self.install.tmp, env={**self.env, **extra_env},
            capture_output=True, text=True, check=False, timeout=180,
        )

    def assert_image(self, target: Path, expected: dict) -> None:
        self.assertEqual(fixture.checker.build_manifest(target), expected)
        record = json.loads((target / RECORD).read_text(encoding="utf-8"))
        self.assertEqual((record["version"], record["status"]), (2, "current"))
        self.assertEqual(record["source_dir"], str(self.source.resolve()))
        self.assertEqual(record["projection"], expected["projection"])
        for key in ("source_content_sha256", "installed_content_sha256"):
            self.assertEqual(record[key], expected["content_sha256"])
        for key in ("source_file_count", "installed_file_count"):
            self.assertEqual(record[key], expected["file_count"])
        self.assertFalse((target / "tests").exists())

    def real_install(self) -> None:
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_image(self.install.target, self.expected)

    def prepare_replacement(self) -> dict:
        before = fixture.snapshot(self.source)
        security = self.source / "SECURITY.md"
        security.write_bytes(security.read_bytes() + b"\nEXAMPLE disposable replacement evidence.\n")
        after = fixture.snapshot(self.source)
        self.assertEqual(set(before), set(after))
        self.assertEqual({path for path in before if before[path] != after[path]}, {"SECURITY.md"})
        replacement = fixture.checker.build_manifest(self.source)
        self.assertNotEqual(replacement["content_sha256"], self.expected["content_sha256"])
        self.assertEqual(
            fixture.checker.compare_manifests(self.expected, replacement)["changed_files"], ["SECURITY.md"],
        )
        return replacement

    def consume_without_source(self) -> None:
        self.assertEqual(self.source, self.install.tmp / "source")
        self.assertNotEqual(self.source.resolve(), fixture.ROOT.resolve())
        shutil.rmtree(self.source)
        self.assertFalse(self.source.exists())
        before = fixture.snapshot(self.install.tmp)
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-X", "int_max_str_digits=4300",
             "-c", PROBE, str(self.install.target),
             str(fixture.ROOT.resolve()), str(self.source), str(self.install.tmp)],
            cwd=self.install.tmp / "home", env=self.env,
            input=json.dumps({"manifest": self.expected, "inputs": self.inputs}),
            capture_output=True, text=True, check=False, timeout=60,
        )
        after = fixture.snapshot(self.install.tmp)
        def retained(image: dict) -> dict:
            return {path: value for path, value in image.items() if not path.startswith("outputs/")}
        self.assertEqual(retained(before), retained(after))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertIs(report["ok"], True)
        self.assertEqual((report["forbidden"], report["actions"]), (0, 0))
        self.assertEqual(report["controls"], 11)
        self.assertEqual(report["cli_cases"], 16)
        self.assertEqual(report["int_max_str_digits"], 4300)
        self.assertEqual(report["int_max_str_digits_option"], "4300")
        self.assertEqual(
            report["native_integer"], {"at_limit": "integer-parsed", "over_limit": "conversion-refused"},
        )
        self.assertGreaterEqual(report["origins"], 6)
        self.assertGreater(report["reads"]["installed"], 0)
        self.assertGreater(report["reads"]["input"], 0)
        self.assertGreater(report["writes"], 0)
        self.assertGreater(report["mutations"], 0)

    def test_installed_consumers_lifecycle_without_source(self) -> None:
        self.assertEqual(self.install.leftovers(), [])
        shared = RestoredInstalledRows(self)
        shared.exercise_rollbacks()
        shared.retain()
        with self.subTest(rows=("fresh", "activation-rollback", "term-rollback")):
            self.consume_without_source()

    def rollback(self, mode: str) -> None:
        previous = fixture.snapshot(self.install.target)
        replacement = self.prepare_replacement()
        source_before = fixture.snapshot(self.source)
        witness, event = self.install.tmp / ("EXAMPLE_witness_" + mode), self.install.tmp / ("EXAMPLE_event_" + mode)
        shim = self.install.shims / "mv"
        self.addCleanup(shim.unlink, missing_ok=True)
        self.install.write_shim("mv", MV_SHIM)
        try:
            result = self.run_install(
                CWO_TEST_INTERRUPT=mode, CWO_TEST_TARGET=str(self.install.target),
                CWO_TEST_SKILLS=str(self.install.skills), CWO_TEST_BACKUPS=str(self.install.backups),
                CWO_TEST_SKILL=fixture.SKILL, CWO_TEST_WITNESS=str(witness), CWO_TEST_EVENT=str(event),
            )
        finally:
            shim.unlink(missing_ok=True)
        if mode == "term":
            self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("could not activate staged install", result.stderr)
        self.assertIn(f"Restored the previous install at {self.install.target}", result.stderr.splitlines())
        self.assertEqual(fixture.snapshot(self.install.target), previous)
        self.assertEqual(fixture.snapshot(self.source), source_before)
        self.assertEqual(self.install.leftovers(), [])
        stage, backup = (Path(line) for line in event.read_text(encoding="utf-8").splitlines())
        self.assertEqual(stage.parent, self.install.skills)
        self.assertTrue(stage.name.startswith(f".{fixture.SKILL}.stage."))
        self.assertEqual(backup.parent, self.install.backups)
        self.assertTrue(backup.name.startswith(f"{fixture.SKILL}.prev."))
        self.assert_image(witness, replacement)
        self.assert_image(self.install.target, self.expected)
        shutil.rmtree(witness)

    def test_replacement_installed_consumers_without_source(self) -> None:
        previous = fixture.snapshot(self.install.target)
        self.expected = self.prepare_replacement()
        self.real_install()
        backups = list(self.install.backups.glob(f"{fixture.SKILL}.prev.*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(fixture.snapshot(backups[0]), previous)
        self.assertEqual(list(self.install.skills.glob(f".{fixture.SKILL}.stage.*")), [])
        self.consume_without_source()


if __name__ == "__main__":
    unittest.main()
