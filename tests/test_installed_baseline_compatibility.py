"""Installed baseline consumers after disposable installation and rollback."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

from tests import test_install_projection as fixture
from tests.test_installed_numeric_rollback import MV_SHIM


RECORD = ".cwo-install-manifest.json"
MODULE = "scripts/cwo_core/requirement_baseline.py"
INPUTS = fixture.ROOT / "tests/fixtures/requirement-baseline"

# No installed test helpers: this fixed child imports the installed product only.
PROBE = r'''
import contextlib
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request
from unittest.mock import patch

root, checkout, source = (Path(value).resolve() for value in sys.argv[1:4])
payload = json.load(sys.stdin)
scripts = root / "scripts"
assert root != source and not root.is_relative_to(checkout)
assert not any(name == "cwo_core" or name.startswith("cwo_core.") for name in sys.modules)
assert all(not Path(item).resolve().is_relative_to(checkout) for item in sys.path)
assert all(not Path(item).resolve().is_relative_to(source) for item in sys.path)
assert source.exists() is (not payload["source_gone"])
sys.path.insert(0, str(scripts))
opened, writes, source_reads, processes, networks = [], [], [], [], []

def under(path, directory):
    return path == directory or path.startswith(directory + os.sep)

def audit(event, args):
    if event == "open":
        path, _mode, flags = args
        if isinstance(path, int):
            return
        path = os.path.realpath(os.path.abspath(os.fsdecode(path)))
        if any(under(path, str(directory)) for directory in (checkout, source)):
            source_reads.append(path)
            raise RuntimeError("source guard reached")
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            writes.append(path)
            raise RuntimeError("write guard reached")
        opened.append(path)
    elif event in {
        "subprocess.Popen", "os.system", "os.exec", "os.spawn",
        "os.posix_spawn", "os.fork", "os.forkpty",
    }:
        processes.append(event)
        raise RuntimeError("process guard reached")
    elif event.startswith("socket."):
        networks.append(event)
        raise RuntimeError("network guard reached")

# Starts before all CWO imports, input reads and tested consumer calls.
sys.addaudithook(audit)

@contextlib.contextmanager
def limited():
    previous = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(4300)
        yield
    finally:
        sys.set_int_max_str_digits(previous)

def digest(record):
    raw = json.dumps(record, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False, allow_nan=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()

def refused(action):
    try:
        action()
    except rb.RequirementBaselineError as error:
        return error
    raise AssertionError("expected RequirementBaselineError")

def loader_cases(baseline, invalid):
    for version in (1, 2**100):
        record = dict(baseline, baseline_version=version)
        loaded = rb.load_record(json.dumps(record))
        assert loaded == record and rb.baseline_errors(loaded) == []
        assert rb.record_digest(loaded) == digest(record)
    duplicate = refused(lambda: rb.load_record('{"bead_id":"a","bead_id":"b"}'))
    assert duplicate.errors == ["duplicate key(s) bead_id"] and duplicate.__cause__ is None
    malformed = refused(lambda: rb.load_record("{"))
    assert type(malformed.__cause__) is json.JSONDecodeError
    assert malformed.errors == [f"not JSON: {malformed.__cause__}"]
    for text in ("[]", "null", "1"):
        error = refused(lambda: rb.load_record(text))
        assert error.errors == ["a record must be a JSON object"] and error.__cause__ is None
    with limited():
        try:
            json.loads(invalid)
        except ValueError as native:
            assert type(native) is ValueError
            message = str(native)
        else:
            raise AssertionError("native integer conversion did not fail")
        error = refused(lambda: rb.load_record(invalid))
    assert type(error.__cause__) is ValueError and str(error.__cause__) == message
    assert error.errors == ["not JSON: " + message]
    return message

def readiness_cases(paths, baseline, amendment, message):
    chain = readiness.load_baseline_chain(paths["baseline"], [paths["amendment"]])
    assert chain == rb.resolve_chain(baseline, [amendment])
    assert chain["version"] == 2 and chain["amendment_ids"] == ["add-changelog"]
    assert chain["digest"] == digest(amendment["baseline"])
    failures = []
    for initial, amendments in ((paths["invalid"], []), (paths["baseline"], [paths["invalid"]])):
        with patch.object(readiness, "resolve_chain", wraps=rb.resolve_chain) as resolve:
            with limited():
                error = refused(lambda: readiness.load_baseline_chain(initial, amendments))
            resolve.assert_not_called()
        assert type(error.__cause__) is ValueError
        assert error.errors == ["not JSON: " + message]
        failures.append(error.errors)
    return {"version": chain["version"], "digest": chain["digest"], "refusals": failures}

def cli_cases(paths, message):
    output = paths["baseline"].parent / "never-written.json"
    record = ["record", "--repo", str(root), "--base-commit", "0" * 40,
              "--scope", ".", "--output", str(output), "--json"]
    verify = ["verify", "--repo", str(root), "--baseline", str(paths["baseline"]),
              "--candidate", str(paths["invalid"]), "--json"]
    cases = [
        (record + ["--baseline", str(paths["invalid"])], "recorded"),
        (record + ["--baseline", str(paths["baseline"]), "--amendment", str(paths["invalid"])], "recorded"),
        (verify + ["--bead-json", str(output)], "valid"),
        (verify + ["--read-beads"], "valid"),
    ]
    results = []
    for argv, field in cases:
        out, err = io.StringIO(), io.StringIO()
        with patch.object(cli, "capture_candidate", wraps=cli.capture_candidate) as capture, \
                patch.object(cli, "_bead_projection", wraps=cli._bead_projection) as projection, \
                patch.object(cli, "check_candidate", wraps=cli.check_candidate) as check, \
                patch.object(beads, "run_bd") as bd, patch.object(beads, "run_bd_structured") as structured, \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with limited():
                code = cli.main(argv)
            result = json.loads(out.getvalue())
            assert code == 1 and result[field] is False and err.getvalue() == ""
            assert result["errors"] == ["not JSON: " + message]
            for spy in (capture, projection, check, bd, structured):
                spy.assert_not_called()
            assert not output.exists()
        results.append({"argv": argv, "field": field, "result": result})
    return results

def bindings():
    result = {}
    for name, module in list(sys.modules.items()):
        if name == "cwo_core" or name.startswith("cwo_core."):
            file = Path(module.__file__).resolve()
            assert file.is_relative_to(scripts / "cwo_core"), (name, file)
        elif name in ("candidate_identity", "validate_run_readiness_plan", "check_installed_skill"):
            file = scripts / (name + ".py")
        else:
            continue
        assert Path(module.__file__).resolve() == file
        assert Path(module.__spec__.origin).resolve() == file
        if hasattr(module, "__path__"):
            assert [Path(item).resolve() for item in module.__path__] == [file.parent]
            assert [Path(item).resolve() for item in module.__spec__.submodule_search_locations] == [file.parent]
        result[name] = {"file": str(file), "origin": str(module.__spec__.origin)}
    return result

def consume():
    global rb, readiness, cli, beads
    rb = importlib.import_module("cwo_core.requirement_baseline")
    readiness = importlib.import_module("validate_run_readiness_plan")
    cli = importlib.import_module("candidate_identity")
    beads = importlib.import_module("cwo_core.beads")
    checker = importlib.import_module("check_installed_skill")
    assert checker.REPO_ROOT == root
    assert checker.build_manifest(root) == payload["manifest"]
    for relative in ("SECURITY.md", "policy/install-projection.yaml"):
        actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        expected = next(item["sha256"] for item in payload["manifest"]["files"] if item["path"] == relative)
        assert actual == expected, relative
    texts, paths, inputs = {}, {}, {}
    for name, item in payload["inputs"].items():
        path = Path(item["path"])
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == item["sha256"]
        paths[name], texts[name] = path, raw.decode("utf-8")
        inputs[name] = {"path": str(path), "sha256": item["sha256"]}
    baseline = rb.load_record(texts["baseline"])
    amendment = rb.load_record(texts["amendment"])
    message = loader_cases(baseline, texts["invalid"])
    return {"inputs": inputs, "loader": ["supported", "large", "duplicate", "malformed", "nonobject", "native"],
            "readiness": readiness_cases(paths, baseline, amendment, message),
            "cli": cli_cases(paths, message)}

def control(action, diagnostic):
    try:
        action()
    except RuntimeError as error:
        assert str(error) == diagnostic
    else:
        raise AssertionError("guard control did not refuse")

failure, result = None, None
with patch("subprocess.Popen", side_effect=RuntimeError("Popen guard reached")) as process, \
        patch("urllib.request.urlopen", side_effect=RuntimeError("urlopen guard reached")) as network:
    try:
        result = consume()
    except BaseException as error:
        failure = error
    origins = bindings()
    observed = [process.call_count, network.call_count, len(processes), len(networks),
                len(writes), len(source_reads)]
    measured_opened = list(opened)
    assert observed == [0, 0, 0, 0, 0, 0], observed
    control(lambda: subprocess.Popen(["never-start"]), "Popen guard reached")
    control(lambda: urllib.request.urlopen("https://never-connect.invalid"), "urlopen guard reached")
    control(lambda: sys.audit("subprocess.Popen", None, None, None, None), "process guard reached")
    control(lambda: sys.audit("socket.connect", None, None), "network guard reached")
    control(lambda: open(Path.cwd() / "never-created", "w"), "write guard reached")
    for directory in (checkout, source):
        control(lambda: open(directory / "README.md", "rb"), "source guard reached")
    controls = [process.call_count, network.call_count, len(processes), len(networks),
                len(writes), len(source_reads)]
    assert controls == [1, 1, 1, 1, 1, 2], controls
report = {"ok": failure is None, "result": result, "origins": origins, "opened": measured_opened,
          "source_gone": not source.exists(), "observed": observed, "controls": controls}
if failure is not None:
    report["error"] = {"type": type(failure).__name__, "message": str(failure)}
print(json.dumps(report, sort_keys=True))
if failure is not None:
    raise failure
'''


class InstalledBaselineCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.input_bytes = {}
        cls.input_stats = {}
        for name, filename in (("baseline", "baseline-v1.json"), ("amendment", "amendment-adds-criterion.json")):
            path = INPUTS / filename
            cls.input_bytes[name] = path.read_bytes()
            cls.input_stats[path] = path.stat()

    @classmethod
    def tearDownClass(cls) -> None:
        for path, before in cls.input_stats.items():
            after = path.stat()
            for field in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns"):
                if getattr(before, field) != getattr(after, field):
                    raise AssertionError(f"immutable baseline fixture metadata changed: {path.name}/{field}")

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
            "SKILL_VALIDATOR": str(self.install.tmp / "no-validator.py"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PATH": str(self.install.shims) + os.pathsep + os.environ.get("PATH", os.defpath),
        }
        for key in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "BASH_ENV", "ENV"):
            self.env.pop(key, None)
        self.inputs = {}
        directory = self.install.tmp / "inputs"
        directory.mkdir()
        values = {**self.input_bytes, "invalid": ('{"baseline_version":' + "9" * 4400 + "}").encode("utf-8")}
        for name, raw in values.items():
            path = directory / (name + ".json")
            path.write_bytes(raw)
            self.inputs[name] = {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}
        self.expected = fixture.checker.build_manifest(self.source)
        self.first = self.real_install()

    def _cleanup_install(self) -> None:
        temporary = getattr(self.install, "_tmp", None)
        try:
            self.install.doCleanups()
        finally:
            if temporary is not None:
                temporary.cleanup()

    def run_install(self, **extra_env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(self.source / "scripts/install.sh"), "--skills-dir", str(self.install.skills), "--yes"],
            cwd=self.install.tmp, env={**self.env, **extra_env},
            capture_output=True, text=True, check=False, timeout=180,
        )

    def real_install(self) -> dict:
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(fixture.checker.build_manifest(self.install.target), self.expected)
        record = json.loads((self.install.target / RECORD).read_text(encoding="utf-8"))
        self.assertEqual((record["version"], record["status"]), (2, "current"))
        self.assertEqual(record["source_dir"], str(self.source.resolve()))
        for field in ("source_content_sha256", "installed_content_sha256"):
            self.assertEqual(record[field], self.expected["content_sha256"])
        self.assertEqual(record["installed_file_count"], self.expected["file_count"])
        self.assertEqual(record["projection"], self.expected["projection"])
        self.assertFalse((self.install.target / "tests").exists())
        return record

    def remove_source(self) -> None:
        self.assertEqual(self.source.parent, self.install.tmp)
        self.assertNotEqual(self.source.resolve(), fixture.ROOT.resolve())
        shutil.rmtree(self.source)
        self.assertFalse(self.source.exists())

    def probe(self, *, source_gone: bool = True, missing: bool = False) -> None:
        before = fixture.snapshot(self.install.tmp)
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", PROBE, str(self.install.target),
             str(fixture.ROOT), str(self.source)],
            input=json.dumps({"manifest": self.expected, "inputs": self.inputs, "source_gone": source_gone}),
            cwd=self.install.tmp / "home", env=self.env,
            capture_output=True, text=True, check=False, timeout=60,
        )
        self.assertEqual(fixture.snapshot(self.install.tmp), before)
        self.assertTrue(result.stdout, result.stderr)
        print(result.stdout, end="")
        report = json.loads(result.stdout)
        self.assertEqual(report["observed"], [0, 0, 0, 0, 0, 0])
        self.assertEqual(report["controls"], [1, 1, 1, 1, 1, 2])
        self.assertEqual(report["source_gone"], source_gone)
        if missing:
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIs(report["ok"], False)
            self.assertEqual(report["error"], {
                "type": "ModuleNotFoundError", "message": "No module named 'cwo_core.requirement_baseline'",
            })
            self.assertIn("ModuleNotFoundError: No module named 'cwo_core.requirement_baseline'", result.stderr)
            return
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIs(report["ok"], True)
        for name in ("cwo_core.requirement_baseline", "candidate_identity", "validate_run_readiness_plan"):
            self.assertIn(name, report["origins"])
        for item in self.inputs.values():
            self.assertIn(item["path"], report["opened"])
        self.assertEqual(len(report["result"]["cli"]), 4)

    def dependency_control(self) -> None:
        (self.install.target / MODULE).unlink()
        self.probe(missing=True)

    def prepare_replacement(self) -> dict:
        before = fixture.snapshot(self.source)
        security = self.source / "SECURITY.md"
        security.write_bytes(security.read_bytes() + b"\nPrivate installed baseline replacement marker.\n")
        after = fixture.snapshot(self.source)
        self.assertEqual(set(before), set(after))
        self.assertEqual({path for path in before if before[path] != after[path]}, {"SECURITY.md"})
        expected = fixture.checker.build_manifest(self.source)
        self.assertNotEqual(expected["content_sha256"], self.expected["content_sha256"])
        self.assertEqual(fixture.checker.compare_manifests(self.expected, expected)["changed_files"], ["SECURITY.md"])
        return expected

    def test_fresh_source_gone_baseline_consumers_and_missing_dependency(self) -> None:
        self.assertEqual(self.install.leftovers(), [])
        self.remove_source()
        self.probe()
        self.dependency_control()

    def test_replacement_source_gone_baseline_consumers(self) -> None:
        self.probe(source_gone=False)
        previous = fixture.snapshot(self.install.target)
        self.expected = self.prepare_replacement()
        second = self.real_install()
        self.assertNotEqual(second["installed_content_sha256"], self.first["installed_content_sha256"])
        backups = sorted(self.install.backups.glob(f"{fixture.SKILL}.prev.*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(fixture.snapshot(backups[0]), previous)
        self.assertEqual(list(self.install.skills.glob(f".{fixture.SKILL}.stage.*")), [])
        self.remove_source()
        self.probe()

    def test_term_rollback_restores_source_gone_baseline_consumers(self) -> None:
        self.probe(source_gone=False)
        previous = fixture.snapshot(self.install.target)
        replacement = self.prepare_replacement()
        source_before = fixture.snapshot(self.source)
        witness = self.install.tmp / "staged-witness"
        event = self.install.tmp / "interruption-paths"
        shim = self.install.shims / "mv"
        self.addCleanup(shim.unlink, missing_ok=True)
        self.install.write_shim("mv", MV_SHIM)
        try:
            result = self.run_install(
                CWO_TEST_INTERRUPT="term", CWO_TEST_TARGET=str(self.install.target),
                CWO_TEST_SKILLS=str(self.install.skills), CWO_TEST_BACKUPS=str(self.install.backups),
                CWO_TEST_SKILL=fixture.SKILL, CWO_TEST_WITNESS=str(witness), CWO_TEST_EVENT=str(event),
            )
        finally:
            shim.unlink(missing_ok=True)
        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        self.assertIn(f"Restored the previous install at {self.install.target}", result.stderr.splitlines())
        self.assertEqual(fixture.snapshot(self.install.target), previous)
        self.assertEqual(fixture.snapshot(self.source), source_before)
        self.assertEqual(self.install.leftovers(), [])
        stage, backup = (Path(line) for line in event.read_text(encoding="utf-8").splitlines())
        self.assertEqual(stage.parent, self.install.skills)
        self.assertTrue(stage.name.startswith(f".{fixture.SKILL}.stage."))
        self.assertEqual(backup.parent, self.install.backups)
        self.assertTrue(backup.name.startswith(f"{fixture.SKILL}.prev."))
        self.assertEqual(fixture.checker.build_manifest(witness), replacement)
        record = json.loads((witness / RECORD).read_text(encoding="utf-8"))
        self.assertEqual(record["installed_content_sha256"], replacement["content_sha256"])
        self.assertEqual(record["source_content_sha256"], replacement["content_sha256"])
        self.assertEqual(record["source_dir"], str(self.source.resolve()))
        shutil.rmtree(witness)
        self.remove_source()
        self.probe()


if __name__ == "__main__":
    unittest.main()
