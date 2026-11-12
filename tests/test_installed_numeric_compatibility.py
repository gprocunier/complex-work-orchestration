"""Disposable installed consumers of the fixed predecessor captures."""
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


GOLDEN = fixture.ROOT / "tests/fixtures/w20_numeric_predecessor_v1.json"
GOLDEN_SHA256 = (
    "cf713c8418d67a5d7dd334b728f00a2e0af08b10475c7630ee474673a3bb8218"
)
RECORD = ".cwo-install-manifest.json"
MODULE = "scripts/cwo_core/native_progress.py"
POLICY = "policy/native-worker-execution.yaml"

# Only this fixed program is executed; fixture fields never select code or paths.
PROBE = r'''
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request
from copy import deepcopy
from unittest.mock import patch

root, original, source = (Path(value).resolve() for value in sys.argv[1:4])
raw = sys.stdin.buffer.read()
assert hashlib.sha256(raw).hexdigest() == sys.argv[4]
document = json.loads(raw)
scripts = root / "scripts"
assert not root.is_relative_to(original) and not root.is_relative_to(source)
assert not any(name == "cwo_core" or name.startswith("cwo_core.") for name in sys.modules)
assert all(not Path(item).resolve().is_relative_to(original) for item in sys.path)
sys.path.insert(0, str(scripts))
opened, source_reads, write_opens, processes, networks = [], [], [], [], []
forbidden = (str(original), str(source))

def under(path, directory):
    return path == directory or path.startswith(directory + os.sep)

def audit_open(args):
    path, _mode, flags = args
    if isinstance(path, int):
        return
    path = os.path.realpath(os.path.abspath(os.fsdecode(path)))
    if any(under(path, directory) for directory in forbidden):
        source_reads.append(path)
        raise RuntimeError("source open guard reached")
    if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
        write_opens.append(path)
        raise RuntimeError("write open guard reached")
    if under(path, str(root)):
        opened.append(path)

def audit(event, args):
    if event == "open":
        audit_open(args)
    elif event in {
        "subprocess.Popen", "os.system", "os.exec", "os.spawn",
        "os.posix_spawn", "os.fork", "os.forkpty",
    }:
        processes.append(event)
        raise RuntimeError("process audit guard reached")
    elif event.startswith("socket."):
        networks.append(event)
        raise RuntimeError("network audit guard reached")

# Test instrumentation starts here, before every CWO import.
sys.addaudithook(audit)

def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

def golden(case, current):
    expected = canonical(case["expected"])
    assert hashlib.sha256(expected).hexdigest() == case["canonical_sha256"]
    assert canonical(current) == expected, case["name"]
    assert hashlib.sha256(canonical(current)).hexdigest() == case["canonical_sha256"]

def progress_cases(producer):
    for case in document["progress"]:
        current = producer.evaluate_worker_progress(**deepcopy(case["input"]))
        golden(case, current)
        for decision in (case["expected"], current):
            assert decision["dispatch_authorized"] is False
            assert producer.validate_progress_decision_for_productive_use(decision) is None

def sizing_cases(producer):
    refusal = ["commitment version 1 is historical-inspection-only and dispatch-forbidden"]
    for case in document["work_sizing"]:
        current = producer.evaluate_work_estimate(deepcopy(case["input"]))
        golden(case, current)
        for estimate in (case["expected"], current):
            assert producer.validate_work_estimate(estimate) == []
            assert producer.canonical_work_estimate_sha256(estimate) == case["work_estimate_sha256"]
        legacy = deepcopy(case["legacy_v1_commitment"])
        assert type(legacy["version"]) is int and legacy["version"] == 1
        assert legacy["work_estimate_sha256"] == case["work_estimate_sha256"]
        assert case["legacy_inspection_errors"] == []
        assert case["legacy_current_dispatch_errors"] == refusal
        assert producer.validate_worker_commitment(legacy, current) == []
        assert producer.validate_worker_commitment(legacy, current, dispatchable=False) == []
        assert producer.validate_worker_commitment(legacy, current, dispatchable=True) == refusal
        relabelled = deepcopy(legacy)
        relabelled["version"] = 2
        for field in (
            "confidence", "tool_calls_before_commitment",
            "context_compactions_before_commitment", "reason",
        ):
            relabelled.pop(field)
        relabelled.update(
            packet_id="installed-historical-test", attempt_nonce="installed-historical-test",
            agent_id="installed-historical-test", precommit_receipt_sha256="0" * 64,
        )
        assert producer.validate_worker_commitment(
            relabelled, current, dispatchable=True,
        ) == ["commitment version 2 requires the bound precommit receipt"]

def pool_cases(producer):
    policy = deepcopy(document["proportionality_policy"])
    before = canonical(policy)
    for case in document["proportionality"]:
        current = producer.pool_proportionality_check(
            **deepcopy(case["input"]), policy_document=policy,
        )
        golden(case, current)
        for assessment in (case["expected"], current):
            assert producer.validate_pool_proportionality_assessment(
                assessment, policy_document=policy,
            ) == []
            assert assessment["dispatch_authorized"] is False
            assert assessment["authority"] == "candidate-evidence-only"
        assert current["accepted"] is (case["name"] == "economically-eligible")
        assert canonical(policy) == before

def cases():
    inventory = {
        "progress": ["ordinary", "warning", "budget-stop", "authority-stop"],
        "work_sizing": ["semantic", "literal", "narrow"],
        "proportionality": ["economically-eligible", "economically-rejected"],
    }
    assert type(document["version"]) is int and document["version"] == 1
    assert document["effect_authority"] is False
    assert document["fixture_type"] == "w20-numeric-predecessor-goldens"
    assert document["baseline_commit"] == "55d99e2666556d949eba33dc590f53a2e1bccad9"
    assert document["baseline_tree"] == "fdbf3ea5117beb0cd4fc56ed976e4ca110d963e3"
    for group, names in inventory.items():
        assert [case["name"] for case in document[group]] == names
    before = canonical(document)
    progress = importlib.import_module("cwo_core.native_progress")
    sizing = importlib.import_module("cwo_core.work_sizing")
    pool = importlib.import_module("cwo_core.native_pool_proportionality")
    policy = importlib.import_module("cwo_core.policy")
    assert Path(policy.POLICY_DIR).resolve() == root / "policy"
    policy.clear_policy_cache()
    policy.load_policy("native-worker-execution")
    assert str(root / "policy/native-worker-execution.yaml") in opened
    progress_cases(progress)
    sizing_cases(sizing)
    pool_cases(pool)
    assert canonical(document) == before
    return [f"{group}/{name}" for group, names in inventory.items() for name in names]

def bindings():
    result = {}
    for name, module in list(sys.modules.items()):
        if name == "cwo_core" or name.startswith("cwo_core."):
            file = Path(module.__file__).resolve()
            origin = Path(module.__spec__.origin).resolve()
            assert file == origin and file.is_relative_to(scripts / "cwo_core"), name
            if hasattr(module, "__path__"):
                assert [Path(item).resolve() for item in module.__path__] == [file.parent]
                assert [
                    Path(item).resolve() for item in module.__spec__.submodule_search_locations
                ] == [file.parent]
            result[name] = {"file": str(file), "origin": str(origin)}
    return result

def refuse(action, message):
    try:
        action()
    except RuntimeError as error:
        assert str(error) == message, str(error)
    else:
        raise AssertionError("guard control did not refuse")

failure, completed = None, []
with patch("subprocess.Popen", side_effect=RuntimeError("Popen guard reached")) as process, \
        patch("urllib.request.urlopen", side_effect=RuntimeError("urlopen guard reached")) as network:
    try:
        completed = cases()
    except BaseException as error:
        failure = error
    origins = bindings()
    observed = [
        process.call_count, network.call_count, len(processes), len(networks),
        len(write_opens), len(source_reads),
    ]
    measured_opened, measured_source = list(opened), list(source_reads)
    assert observed == [0, 0, 0, 0, 0, 0], observed
    # Every control runs after the measured imports, producers and refusals.
    refuse(lambda: subprocess.Popen(["never-start"]), "Popen guard reached")
    refuse(lambda: urllib.request.urlopen("https://never-connect.invalid"), "urlopen guard reached")
    refuse(lambda: sys.audit("subprocess.Popen", None, None, None, None),
           "process audit guard reached")
    refuse(lambda: sys.audit("socket.connect", None, None), "network audit guard reached")
    refuse(lambda: open(Path.cwd() / "never-created", "w"), "write open guard reached")
    for directory in (original, source):
        refuse(lambda: open(directory / "README.md", "rb"), "source open guard reached")
    controls = [
        process.call_count, network.call_count, len(processes), len(networks),
        len(write_opens), len(source_reads),
    ]
    assert controls == [1, 1, 1, 1, 1, 2], controls
report = {
    "ok": failure is None, "cases": completed, "origins": origins,
    "opened": measured_opened, "source_reads": measured_source,
    "observed": observed, "controls": controls,
}
if failure is not None:
    report["error"] = {"type": type(failure).__name__, "message": str(failure)}
print(json.dumps(report, sort_keys=True))
if failure is not None:
    raise failure
'''


class InstalledNumericCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.golden_bytes = GOLDEN.read_bytes()
        if hashlib.sha256(cls.golden_bytes).hexdigest() != GOLDEN_SHA256:
            raise AssertionError("fixed predecessor fixture bytes changed")
        cls.golden_stat = GOLDEN.stat()

    @classmethod
    def tearDownClass(cls) -> None:
        current = GOLDEN.stat()
        for field in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns"):
            if getattr(current, field) != getattr(cls.golden_stat, field):
                raise AssertionError("source fixture metadata changed")

    def setUp(self) -> None:
        self.install = fixture.InstallerProjectionTests(
            "test_fresh_install_is_the_projection_and_its_resources_are_usable"
        )
        self.install.setUp()
        self.addCleanup(self.install.tearDown)
        self.assertFalse(self.install.tmp.resolve().is_relative_to(fixture.ROOT.resolve()))
        self.source = self.install.tmp / "source"
        self.source.mkdir()
        ignore = shutil.ignore_patterns(
            ".git", ".beads", ".orchestration-audit", "__pycache__", "*.pyc", "*.pyo",
        )
        for name, kind in fixture.REQUIRED.items():
            if kind == "file":
                shutil.copy2(fixture.ROOT / name, self.source / name)
            else:
                shutil.copytree(fixture.ROOT / name, self.source / name, ignore=ignore)
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
        self.expected = fixture.checker.build_manifest(self.source)
        self.record = self.real_install()

    def real_install(self) -> dict[str, object]:
        result = subprocess.run(
            ["bash", str(self.source / "scripts/install.sh"),
             "--skills-dir", str(self.install.skills), "--yes"],
            cwd=self.install.tmp, env=self.env, capture_output=True, text=True,
            check=False, timeout=180,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads((self.install.target / RECORD).read_text(encoding="utf-8"))
        self.assertEqual(record["version"], 2)
        self.assertEqual(record["status"], "current")
        self.assertEqual(record["source_dir"], str(self.source.resolve()))
        self.assertEqual(record["installed_content_sha256"], self.expected["content_sha256"])
        self.assertEqual(record["source_content_sha256"], self.expected["content_sha256"])
        self.assertEqual(record["installed_file_count"], self.expected["file_count"])
        self.assertEqual(record["projection"], self.expected["projection"])
        self.assertFalse((self.install.target / "tests").exists())
        return record

    def remove_source(self) -> None:
        self.assertTrue(self.source.is_relative_to(self.install.tmp))
        self.assertNotEqual(self.source.resolve(), fixture.ROOT.resolve())
        shutil.rmtree(self.source)
        self.assertFalse(self.source.exists())

    def probe(self) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        before = fixture.snapshot(self.install.tmp)
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", PROBE, str(self.install.target),
             str(fixture.ROOT), str(self.source), GOLDEN_SHA256],
            input=self.golden_bytes.decode("utf-8"), cwd=self.install.tmp / "home",
            env=self.env, capture_output=True, text=True, check=False, timeout=60,
        )
        self.assertEqual(fixture.snapshot(self.install.tmp), before)
        self.assertTrue(result.stdout, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["observed"], [0, 0, 0, 0, 0, 0])
        self.assertEqual(report["controls"], [1, 1, 1, 1, 1, 2])
        self.assertEqual(report["source_reads"], [])
        for name, binding in report["origins"].items():
            with self.subTest(module=name):
                self.assertEqual(binding["file"], binding["origin"])
                self.assertTrue(
                    Path(binding["file"]).is_relative_to(self.install.target.resolve() / "scripts/cwo_core")
                )
        return result, report

    def positive(self) -> None:
        result, report = self.probe()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIs(report["ok"], True)
        self.assertEqual(len(report["cases"]), 9)
        for name in ("native_progress", "work_sizing", "native_pool_proportionality", "policy", "paths"):
            expected = str(self.install.target.resolve() / f"scripts/cwo_core/{name}.py")
            self.assertEqual(report["origins"]["cwo_core." + name],
                             {"file": expected, "origin": expected})
        self.assertIn(str(self.install.target.resolve() / POLICY), report["opened"])

    def missing(self, relative: str, error_type: str, diagnostic: str) -> None:
        (self.install.target / relative).unlink()
        result, report = self.probe()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIs(report["ok"], False)
        self.assertEqual(report["error"], {"type": error_type, "message": diagnostic})
        self.assertIn(diagnostic, result.stderr)

    def test_replacement_source_gone_and_missing_numeric_dependency(self) -> None:
        self.positive()
        marker = self.install.target / "LOCAL_NUMERIC_MARKER"
        marker.write_text("private replacement sentinel\n", encoding="utf-8")
        second = self.real_install()
        self.assertEqual(second["installed_content_sha256"], self.record["installed_content_sha256"])
        self.assertFalse(marker.exists())
        backups = sorted(self.install.backups.glob(f"{fixture.SKILL}.prev.*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual((backups[0] / marker.name).read_text(encoding="utf-8"),
                         "private replacement sentinel\n")
        self.assertEqual(json.loads((backups[0] / RECORD).read_text(encoding="utf-8")), self.record)
        self.remove_source()
        self.positive()
        self.missing(MODULE, "ModuleNotFoundError", "No module named 'cwo_core.native_progress'")


    def test_fresh_source_gone_and_missing_numeric_dependency(self) -> None:
        self.remove_source()
        self.positive()
        self.missing(MODULE, "ModuleNotFoundError", "No module named 'cwo_core.native_progress'")


    def test_separate_fresh_source_gone_and_missing_installed_policy(self) -> None:
        self.remove_source()
        self.positive()
        self.missing(POLICY, "SystemExit",
                     "missing policy file: policy/native-worker-execution.yaml")


if __name__ == "__main__":
    unittest.main()
