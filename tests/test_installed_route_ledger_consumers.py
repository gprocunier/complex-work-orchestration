"""Conditional reliability checks for the installed route and ledger consumer."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import traceback
import unittest
from unittest.mock import patch

from tests.installed_consumer_fixtures import RestoredInstalledRows
from tests import test_install_projection as fixture
from tests.test_installed_numeric_rollback import MV_SHIM


RECORD = ".cwo-install-manifest.json"
CASES = 12
EVIDENCE_SCHEMA = "cwo-installed-route-consumer-evidence-v1"
EVIDENCE_PREFIX = "CWO_INSTALLED_ROUTE_EVIDENCE "
MAX_EVIDENCE_BYTES = 64 * 1024
PARENT_TIMEOUT_PREFIX = "EXAMPLE reliability parent subprocess timeout: "


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode("ascii")).hexdigest()


def file_identity(path):
    return {"path": str(path.resolve()),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


PROBE = r'''
import contextlib
import copy
import hashlib
import importlib
import inspect
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
from unittest.mock import patch

root, checkout, source, area = (Path(value).resolve() for value in sys.argv[1:5])
context = json.load(sys.stdin)
scripts = root / "scripts"
library = Path(os.__file__).resolve().parent
helper_name = "prepare_route_ledger_reconciliation"
false_fields = (
    "operative", "qualified", "effect_authority", "ledger_snapshot_authenticated",
    "external_completeness_authenticated", "actual_quota_known", "actual_provider_billing_known",
)
effects = dict.fromkeys((
    "read", "write", "mutation", "process-run", "process-Popen", "process-audit",
    "socket", "temporary-directory", "temporary-file", "ledger-open", "ledger-lock",
    "ledger-mutation", "owner", "local-ledger-open",
    "beads-create", "beads-link", "beads-run", "beads-structured",
), 0)
reads = {"installed": set(), "input": set(), "library": set()}
calls = dict.fromkeys(("planner", "validator", "charge"), 0)
consumer_calls = dict.fromkeys(("prepare", "main", "_decode", "_pairs"), 0)
declared = {Path(item["path"]).resolve() for item in context["inputs"].values()}
descriptors, opening = {}, []
real_open, real_close = os.open, os.close

class EffectRefused(RuntimeError):
    pass

def block(name):
    effects[name] += 1
    raise EffectRefused(name)

def path_for(value, directory=None):
    if isinstance(value, int):
        if value not in descriptors:
            block("read")
        return descriptors[value]
    path = Path(os.fsdecode(value))
    if directory not in (None, -1) and not path.is_absolute():
        path = path_for(directory) / path
    return path.resolve()

def observe(path, flags):
    if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
        block("write")
    if path.is_relative_to(root):
        label = "installed"
    elif path in declared:
        label = "input"
    elif path.is_relative_to(library) and not {"site-packages", "dist-packages"} & set(path.parts):
        label = "library"
    else:
        block("read")
    reads[label].add(str(path))

def audit(event, args):
    if event == "open":
        path = opening[-1] if opening else path_for(args[0])
        observe(path, args[2] or 0)
    elif event in {"os.listdir", "os.scandir"}:
        observe(path_for(args[0]), 0)
    elif event in {
        "os.remove", "os.rmdir", "os.mkdir", "os.rename", "os.link", "os.symlink",
        "os.chmod", "os.chown", "os.truncate", "os.utime",
    }:
        block("mutation")
    elif event in {
        "subprocess.Popen", "os.system", "os.exec", "os.spawn", "os.posix_spawn",
        "os.fork", "os.forkpty",
    }:
        block("process-audit")
    elif event.startswith("socket."):
        block("socket")

def open_path(path, flags, *args, **kwargs):
    resolved = path_for(path, kwargs.get("dir_fd"))
    opening.append(resolved)
    try:
        descriptor = real_open(path, flags, *args, **kwargs)
    finally:
        opening.pop()
    descriptors[descriptor] = resolved
    return descriptor

def close_path(descriptor):
    try:
        return real_close(descriptor)
    finally:
        descriptors.pop(descriptor, None)

def guard(name):
    return lambda *args, **kwargs: block(name)

ledger_methods = {
    "__init__": "ledger-open", "_locked": "ledger-lock",
    **dict.fromkeys((
        "open_budget", "reserve", "release", "recover", "_save", "invoke",
        "begin_invocation", "reconcile",
    ), "ledger-mutation"),
}
boundary_calls = {
    ("cwo_core.local_invocation", "open_ledger"): "local-ledger-open",
    ("cwo_core.invocation_ledger", "ProcOwnerProbe.current"): "owner",
    ("cwo_core.beads", "create_bead"): "beads-create",
    ("cwo_core.beads", "add_dependency"): "beads-link",
    ("cwo_core.beads", "run_bd"): "beads-run",
    ("cwo_core.beads", "run_bd_structured"): "beads-structured",
}
producer_calls = {
    ("prepare_route_feasibility", "prepare"): "planner",
    ("cwo_core.invocation_ledger", "validate_ledger"): "validator",
    ("cwo_core.invocation_ledger", "derived_charge"): "charge",
}

def profile(frame, event, _arg):
    if event != "call":
        return
    module, name = frame.f_globals.get("__name__"), frame.f_code.co_qualname
    kind = boundary_calls.get((module, name))
    if module == "cwo_core.invocation_ledger" and name.startswith("InvocationLedger."):
        kind = ledger_methods.get(name.rsplit(".", 1)[-1], kind)
    if kind is not None:
        block(kind)
    counter = producer_calls.get((module, name))
    if counter is not None:
        calls[counter] += 1
    if module == helper_name and name in consumer_calls:
        consumer_calls[name] += 1

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)

def digest(value):
    return hashlib.sha256(canonical(value).encode("ascii")).hexdigest()

def file_identity(path):
    return {"path": str(path.resolve()),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

def diagnostic(error, phase):
    frames, frame = [], error.__traceback__
    while frame is not None and len(frames) < 8:
        frames.append([frame.tb_frame.f_code.co_filename[:1024], frame.tb_frame.f_code.co_name[:128], frame.tb_lineno])
        frame = frame.tb_next
    return {"type": type(error).__name__[:128], "phase": phase[:128],
            "frames": frames}

def image(checker):
    expected = context["manifest"]
    installed = checker.build_manifest(root)
    assert checker.REPO_ROOT == root and installed == expected
    files = {item["path"] for item in expected["files"]}
    directories = {item["path"] for item in expected["entries"] if item["kind"] == "directory"}
    for name in files:
        directories.update(str(parent) for parent in Path(name).parents if str(parent) != ".")
    found = {}
    for path in root.rglob("*"):
        mode = path.lstat().st_mode
        assert stat.S_ISREG(mode) or stat.S_ISDIR(mode)
        found[path.relative_to(root).as_posix()] = "file" if stat.S_ISREG(mode) else "directory"
    assert found == {**dict.fromkeys(files | {".cwo-install-manifest.json"}, "file"),
                     **dict.fromkeys(directories, "directory")}
    record = json.loads((root / ".cwo-install-manifest.json").read_text(encoding="utf-8"))
    assert (record["version"], record["status"], record["source_dir"]) == (2, "current", str(source))
    assert record["projection"] == expected["projection"]
    for key in ("source_content_sha256", "installed_content_sha256"):
        assert record[key] == expected["content_sha256"]
    for key in ("source_file_count", "installed_file_count"):
        assert record[key] == expected["file_count"]
    assert not (root / "tests").exists() and not (root / "tools").exists()
    return {
        "manifests": {
            "expected_sha256": digest(expected), "installed_sha256": digest(installed),
            "content_sha256": installed["content_sha256"], "file_count": installed["file_count"],
            "projection_sha256": installed["projection"]["sha256"],
        },
        "install_record": file_identity(root / ".cwo-install-manifest.json"),
        "security": file_identity(root / "SECURITY.md"),
    }

def check_case(helper, item):
    path = Path(item["path"])
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == item["sha256"]
    payload = json.loads(raw) if item["kind"] == "wrapper" else raw
    original = copy.deepcopy(payload)
    before = dict(calls)
    before_consumer = dict(consumer_calls)
    result = helper.prepare(payload)
    assert (canonical(payload) == canonical(original) if item["kind"] == "wrapper" else payload == original)
    output = io.StringIO()
    code = helper.main(io.BytesIO(raw), output)
    text = output.getvalue()
    assert text.endswith("\n") and text.count("\n") == 1
    assert len(text.encode("ascii")) <= helper.MAX_OUTPUT_BYTES + 1
    cli_result = json.loads(text)
    assert canonical(cli_result) == canonical(result), "EXAMPLE reliability library and CLI results differ"
    assert result["status"] == item["status"]
    assert code == {"within-declared-limits": 0, "invalid": 2,
                    "unassessable": 1, "over-budget": 1}[item["status"]]
    assert all(result[field] is False for field in false_fields)
    assert type(result["reasons"]) is list and len(result["reasons"]) <= 1
    result_sha256 = digest(result)
    joined = {
        "status": result["status"], "result_sha256": result_sha256,
        "library": {"status": result["status"], "result_sha256": result_sha256},
        "cli": {"status": cli_result["status"], "exit": code, "result_sha256": digest(cli_result)},
        "producer_calls": {key: calls[key] - before[key] for key in calls},
        "consumer_calls": {key: consumer_calls[key] - before_consumer[key] for key in consumer_calls},
    }
    if item["kind"] == "raw":
        assert calls == before
        assert result["status"] == "invalid"
        return joined
    assert calls["planner"] >= before["planner"] + 2
    assert calls["validator"] >= before["validator"] + 2
    if item["status"] == "invalid":
        return joined
    assert calls["charge"] > before["charge"]
    assert result["actual_charged"] == item["charged"]
    assert result["planned_totals"] == item["planned"]
    assert len(result["nodes"]) == item["nodes"]
    assert result["completeness_gap"] is bool(item["hidden"])
    assert [row["attempt_id"] for row in result["unmapped_attempts"]] == item["hidden"]
    for resource, total in item["charged"].items():
        assert result["conservative_lower_bound"][resource] >= total
        if item["planned"][resource] is None:
            assert result["still_committed"][resource] is None
            assert result["conservative_total"][resource] is None
            assert all(row["planned"][resource] is None and row["still_committed"][resource] is None
                       for row in result["nodes"])
        else:
            assert result["still_committed"][resource] == 0
            assert result["conservative_total"][resource] == total
    for resource in item["unknown"]:
        assert result["checks"][resource] == "unknown"
    if item["status"] == "over-budget":
        assert result["actual_charged"]["tokens"] > result["limits"]["tokens"]
    return joined

def duplicate_control(helper, outcomes):
    item = context["inputs"]["EXAMPLE_duplicate"]
    before, before_consumer, before_effects = dict(calls), dict(consumer_calls), dict(effects)
    with patch.object(helper, "_pairs", dict):
        try:
            check_case(helper, item)
        except AssertionError as error:
            assert error.args == ("EXAMPLE reliability library and CLI results differ",)
        else:
            raise AssertionError("EXAMPLE reliability duplicate control missed the omitted check")
        output = io.StringIO()
        code = helper.main(io.BytesIO(Path(item["path"]).read_bytes()), output)
        text = output.getvalue()
        assert text.endswith("\n") and text.count("\n") == 1
        assert len(text.encode("ascii")) <= helper.MAX_OUTPUT_BYTES + 1
        permissive = json.loads(text)
    actual = {row["name"]: row for row in outcomes}
    assert code == 0 and permissive["status"] == "within-declared-limits"
    assert digest(permissive) == actual["EXAMPLE_tiny"]["result_sha256"]
    assert effects == before_effects
    return {
        "case": "EXAMPLE_duplicate", "positive": "EXAMPLE_tiny",
        "test_failure": "AssertionError", "phase": "consumer-EXAMPLE_duplicate",
        "strict_result_sha256": actual["EXAMPLE_duplicate"]["result_sha256"],
        "permissive_result_sha256": digest(permissive), "cli_exit": code,
        "producer_calls": {key: calls[key] - before[key] for key in calls},
        "consumer_calls": {key: consumer_calls[key] - before_consumer[key] for key in consumer_calls},
    }

def bindings():
    found = []
    names = {helper_name, "prepare_route_feasibility", "check_installed_skill"}
    for name, module in list(sys.modules.items()):
        if not (name in names or name == "cwo_core" or name.startswith("cwo_core.")):
            continue
        relative = name.replace(".", "/")
        relative += "/__init__.py" if hasattr(module, "__path__") else ".py"
        path = scripts / relative
        assert Path(module.__file__).resolve() == path
        assert Path(module.__spec__.origin).resolve() == path
        if hasattr(module, "__path__"):
            assert [Path(value).resolve() for value in module.__path__] == [path.parent]
            assert [Path(value).resolve() for value in module.__spec__.submodule_search_locations] == [path.parent]
        assert str(path) in reads["installed"]
        assert len(found) < 128
        assert len(name) <= 128 and len(str(path)) <= 1024
        found.append({"name": name, "package": hasattr(module, "__path__"),
                      **file_identity(path)})
    assert names | {"cwo_core", "cwo_core.invocation_ledger", "cwo_core.work_sizing",
                    "cwo_core.native_authority", "cwo_core.local_invocation", "cwo_core.beads"} <= {item["name"] for item in found}
    assert not any(name == "tests" or name.startswith("tests.") for name in sys.modules)
    return sorted(found, key=lambda item: item["name"])

def invoke_guarded(function):
    args, kwargs = [], {}
    for parameter in inspect.signature(function).parameters.values():
        if parameter.default is not inspect.Parameter.empty:
            continue
        if parameter.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD):
            args.append("EXAMPLE_RELIABILITY_UNUSED")
        elif parameter.kind == inspect.Parameter.KEYWORD_ONLY:
            kwargs[parameter.name] = "EXAMPLE_RELIABILITY_UNUSED"
    return function(*args, **kwargs)

def lock_control(ledger):
    with invoke_guarded(ledger.InvocationLedger._locked):
        raise AssertionError("EXAMPLE reliability ledger lock guard was absent")

def control(name, call):
    before = dict(effects)
    sys.setprofile(profile)
    try:
        call()
    except EffectRefused as error:
        assert error.args == (name,)
    else:
        raise AssertionError("EXAMPLE reliability guard missed its positive control")
    finally:
        sys.setprofile(profile)
    before[name] += 1
    assert effects == before

failure, phase, completed, origins, controls = None, "bootstrap", 0, [], 0
input_records, outcomes, evidence, sensitivity = [], [], None, None
ledger = local = beads = None
captured_out, captured_err = io.StringIO(), io.StringIO()
# Observe reliability boundaries before every installed import and pure consumer call.
sys.addaudithook(audit)
sys.setprofile(profile)
with contextlib.ExitStack() as stack:
    for target, replacement in (
        ("os.open", open_path), ("os.close", close_path),
        ("subprocess.run", guard("process-run")), ("subprocess.Popen", guard("process-Popen")),
        ("tempfile.TemporaryDirectory", guard("temporary-directory")),
        ("tempfile.NamedTemporaryFile", guard("temporary-file")),
    ):
        stack.enter_context(patch(target, replacement))
    try:
        assert sys.flags.isolated and sys.dont_write_bytecode
        assert root == area / "skills/complex-work-orchestration"
        assert source == area / "source" and not source.exists()
        assert not area.is_relative_to(checkout)
        assert Path.cwd() == area / "home" == Path(os.environ["HOME"]).resolve()
        assert all(not Path(value).resolve().is_relative_to(checkout) for value in sys.path)
        assert all(not Path(value).resolve().is_relative_to(source) for value in sys.path)
        assert all(path.parent == area / "inputs" for path in declared)
        assert len(declared) == len(context["inputs"]) == 12
        assert not any(name == "cwo_core" or name.startswith("cwo_core.") for name in sys.modules)
        sys.path.insert(0, str(scripts))
        with contextlib.redirect_stdout(captured_out), contextlib.redirect_stderr(captured_err):
            phase = "installed-imports"
            helper = importlib.import_module(helper_name)
            planner = importlib.import_module("prepare_route_feasibility")
            ledger = importlib.import_module("cwo_core.invocation_ledger")
            local = importlib.import_module("cwo_core.local_invocation")
            beads = importlib.import_module("cwo_core.beads")
            checker = importlib.import_module("check_installed_skill")
            assert helper.planner is planner and helper.ledger is ledger
            assert set(helper.FALSE_FIELDS) == set(false_fields)
            phase = "installed-manifest"
            identities = image(checker)
            for name, item in context["inputs"].items():
                phase = "consumer-" + name
                outcomes.append({"name": name, **check_case(helper, item)})
                input_records.append({"name": name, **file_identity(Path(item["path"]))})
                completed += 1
            phase = "installed-origins"
            origins = bindings()
            assert set(reads["input"]) == {str(path) for path in declared}
            evidence = {
                "schema": "cwo-installed-route-consumer-evidence-v1", "scenario": context["scenario"],
                "inputs": sorted(input_records, key=lambda item: item["name"]),
                "origins": origins,
                "outcomes": sorted(outcomes, key=lambda item: item["name"]),
                **identities,
                "interpreter": {
                    "executable": str(Path(sys.executable).resolve()),
                    "version": list(sys.version_info[:3]), "implementation": sys.implementation.name,
                },
                "authority": dict.fromkeys(false_fields, False), "test_output_only": True,
            }
        assert captured_out.getvalue() == captured_err.getvalue() == ""
        assert not any(effects.values())
    except BaseException as error:
        failure = diagnostic(error, phase)
    measured, observed_calls = dict(effects), dict(calls)
    observed_consumer_calls = dict(consumer_calls)
    try:
        phase = "positive-controls"
        probes = [
            ("read", lambda: open(checkout / "SECURITY.md", "rb")),
            ("read", lambda: open(source / "EXAMPLE_RELIABILITY_BLOCKED", "rb")),
            ("read", lambda: open(area / "home/EXAMPLE_RELIABILITY_PRIVATE", "rb")),
            ("write", lambda: open(root / "SECURITY.md", "w")),
            ("write", lambda: open(next(iter(declared)), "w")),
            ("mutation", lambda: os.mkdir(area / "home/EXAMPLE_RELIABILITY_BLOCKED")),
            ("process-run", lambda: subprocess.run(["EXAMPLE_RELIABILITY_NEVER_RUN"])),
            ("process-Popen", lambda: subprocess.Popen(["EXAMPLE_RELIABILITY_NEVER_RUN"])),
            ("process-audit", lambda: sys.audit("subprocess.Popen", None, None, None, None)),
            ("socket", lambda: socket.socket()),
            ("temporary-directory", lambda: tempfile.TemporaryDirectory()),
            ("temporary-file", lambda: tempfile.NamedTemporaryFile()),
        ]
        if ledger is not None and local is not None and beads is not None:
            probes += [
                ("ledger-open", lambda: ledger.InvocationLedger(area / "EXAMPLE_RELIABILITY_UNUSED")),
                ("ledger-lock", lambda: lock_control(ledger)),
                ("ledger-mutation", lambda: invoke_guarded(ledger.InvocationLedger.reserve)),
                ("owner", lambda: invoke_guarded(ledger.ProcOwnerProbe.current)),
                ("local-ledger-open", lambda: invoke_guarded(local.open_ledger)),
                ("beads-create", lambda: invoke_guarded(beads.create_bead)),
                ("beads-link", lambda: invoke_guarded(beads.add_dependency)),
                ("beads-run", lambda: invoke_guarded(beads.run_bd)),
                ("beads-structured", lambda: invoke_guarded(beads.run_bd_structured)),
            ]
        for name, call in probes:
            control(name, call)
            controls += 1
        assert controls == 21
        if failure is None:
            phase = "duplicate-sensitivity"
            sensitivity = duplicate_control(helper, outcomes)
        phase = "evidence-counts"
        for values in (measured, observed_calls, observed_consumer_calls,
                       {name: len(paths) for name, paths in reads.items()}):
            assert all(type(value) is int and 0 <= value <= 1_000_000 for value in values.values())
    except BaseException as error:
        if failure is None:
            failure = diagnostic(error, phase)
sys.setprofile(None)
ok = failure is None and not any(measured.values())
report = {
    "ok": ok, "failure": failure, "effects": measured, "controls": controls,
    "cases": completed, "origins": len(origins), "producer_calls": observed_calls,
    "reads": {name: len(paths) for name, paths in reads.items()},
    "interpreter": list(sys.version_info[:2]),
    "consumer_calls": observed_consumer_calls,
    "control_effects": dict(effects),
    "duplicate_controls": int(sensitivity is not None), "duplicate_sensitivity": sensitivity,
    "evidence": evidence if ok else None,
}
encoded = canonical(report)
if len(encoded.encode("ascii")) > 64 * 1024:
    report["ok"] = False
    report["evidence"] = None
    if report["failure"] is None:
        report["failure"] = {"type": "AssertionError", "phase": "evidence-output", "frames": []}
    encoded = canonical(report)
print(encoded)
raise SystemExit(0 if report["ok"] else 1)
'''


class InstalledRouteLedgerConsumerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.install = fixture.InstallerProjectionTests(
            "test_fresh_install_is_the_projection_and_its_resources_are_usable"
        )
        self.addCleanup(self._cleanup_install)
        self.install.setUp()
        self.assertFalse(self.install.tmp.resolve().is_relative_to(fixture.ROOT.resolve()))
        self.source = self.install.copy_source()
        self.source_image = fixture.snapshot(self.source)
        self.env = {
            **os.environ, "HOME": str(self.install.tmp / "home"),
            "SKILL_VALIDATOR": str(self.install.tmp / "EXAMPLE_RELIABILITY_NO_VALIDATOR.py"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PATH": str(self.install.shims) + os.pathsep + os.environ.get("PATH", os.defpath),
        }
        for name in (
            "CODEX_HOME", "CODEX_SKILLS_DIR", "PYTHONPATH", "PYTHONHOME",
            "PYTHONSTARTUP", "BASH_ENV", "ENV",
        ):
            self.env.pop(name, None)
        (self.install.tmp / "inputs").mkdir()
        (self.install.tmp / "producers").mkdir()
        (self.install.tmp / "home/EXAMPLE_RELIABILITY_PRIVATE").write_text(
            "EXAMPLE private reliability read control.\n", encoding="utf-8",
        )
        self._make_inputs()
        self.expected = fixture.checker.build_manifest(self.source)
        paths = {item["path"] for item in self.expected["files"]}
        self.assertTrue({
            "SECURITY.md", "policy/install-projection.yaml",
            "scripts/prepare_route_ledger_reconciliation.py", "scripts/prepare_route_feasibility.py",
            "scripts/cwo_core/invocation_ledger.py", "scripts/cwo_core/work_sizing.py",
            "scripts/cwo_core/native_authority.py", "scripts/cwo_core/util.py",
        } <= paths, "EXAMPLE reliability runtime prerequisite is missing")
        self.assertFalse(any(path.startswith(("tests/", "tools/", "evaluation/")) for path in paths))
        self.installations = []
        self.scenario = "fresh"
        self.transition = {"scenario": "fresh", "status": "installed", "leftovers": 0}
        self.real_install()

    def _cleanup_install(self) -> None:
        temporary = getattr(self.install, "_tmp", None)
        try:
            self.install.doCleanups()
        finally:
            if temporary is not None:
                temporary.cleanup()

    def _allocate_producer(self, *args, **kwargs):
        directory = self._temporary(
            *args, **{**kwargs, "dir": self.install.tmp / "producers", "prefix": "EXAMPLE_RELIABILITY_"},
        )
        self.addCleanup(directory.cleanup)
        self.producer_directories.append(directory)
        return directory

    def _producer(self, *, tiny=True, diamond=False):
        route = self.producer_fixture.record(tiny=tiny)
        route["aggregate_id"] = "EXAMPLE_RELIABILITY_AGGREGATE"
        if diamond:
            dependencies = {
                "plan": [], "review": ["plan"], "synthesis": ["plan"],
                "validation": ["review", "synthesis"],
            }
            self.assertTrue({node["id"] for node in route["nodes"]} == set(dependencies),
                            "EXAMPLE reliability route fixture changed")
            for node in route["nodes"]:
                node["depends_on"] = list(dependencies[node["id"]])
                node["lineage_parent"] = next(iter(node["depends_on"]), None)
                node["kind"] = "dependent" if node["depends_on"] else "primary"
            for node in route["task_contract"]["required_roles"]:
                node["depends_on"] = list(dependencies[node["id"]])
        self.producer_fixture.bind(route)
        with patch.object(self.producer_fixture.tempfile, "TemporaryDirectory", self._allocate_producer):
            return self.producer_fixture.Producer(route)

    def _complete(self, producer, order=None) -> None:
        nodes = {node["id"]: node for node in producer.prepared["nodes"]}
        identities = list(nodes) if order is None else order
        self.assertTrue(set(identities) == set(nodes), "EXAMPLE reliability production order is incomplete")
        fixed = producer.clock.now
        for identity in identities:
            producer.add(nodes[identity])
            self.assertTrue(producer.clock.now == fixed, "EXAMPLE reliability fixture clock moved")
        snapshot = producer.snapshot()
        for attempt in snapshot["attempts"].values():
            self.assertTrue((attempt["created_at"], attempt["history"][-1]["at"]) == (fixed, fixed), "EXAMPLE reliability fixed timestamp differs")

    def _save(self, name, payload, status) -> None:
        ledger = self.producer_fixture.ledger
        self.assertTrue(not ledger.validate_ledger(copy.deepcopy(payload["ledger_snapshot"])),
                        "EXAMPLE reliability producer snapshot failed validation")
        prepared = self.producer_fixture.planner.prepare(copy.deepcopy(payload["route_input"]))
        self.assertNotEqual(prepared["status"], "invalid")
        selected = {
            key: attempt for key, attempt in payload["ledger_snapshot"]["attempts"].items()
            if attempt["budget_id"] == payload["expected"]["budget_id"]
        }
        charged = {
            resource: sum(ledger.derived_charge(copy.deepcopy(attempt))[resource]
                          for attempt in selected.values())
            for resource in self.producer_fixture.consumer.RESOURCES
        }
        mapped = set(payload["node_attempts"].values())
        raw = json.dumps(payload, sort_keys=True, ensure_ascii=True, allow_nan=False).encode("ascii")
        self._write(name, raw, {
            "kind": "wrapper", "status": status, "charged": charged,
            "planned": prepared["totals"], "nodes": len(prepared["nodes"]),
            "hidden": sorted(set(selected) - mapped),
            "unknown": [key for key in charged if prepared["totals"][key] is None
                        or prepared["limits"][key] is None],
        })

    def _write(self, name, raw, metadata) -> None:
        path = self.install.tmp / "inputs" / (name + ".json")
        path.write_bytes(raw)
        payload = json.loads(raw) if metadata["kind"] == "wrapper" else raw
        result = self.producer_fixture.consumer.prepare(payload)
        self.assertEqual(result["status"], metadata["status"])
        self.inputs[name] = {**metadata, **file_identity(path), "result_sha256": digest(result)}

    def _make_inputs(self) -> None:
        with patch.object(sys, "dont_write_bytecode", True), patch.object(sys, "path", list(sys.path)):
            self.producer_fixture = importlib.import_module("tests.test_route_ledger_reconciliation_preparation")
        module = self.producer_fixture
        for owner, relative in (
            (module, "tests/test_route_ledger_reconciliation_preparation.py"),
            (module.consumer, "scripts/prepare_route_ledger_reconciliation.py"),
            (module.planner, "scripts/prepare_route_feasibility.py"),
            (module.fixtures, "tests/test_invocation_ledger.py"),
            (sys.modules[module.record.__module__], "tests/test_route_feasibility_preparation.py"),
        ):
            self.assertTrue(Path(owner.__file__).resolve() == fixture.ROOT / relative,
                            "EXAMPLE reliability producer origin differs")
        self.inputs, self.producer_directories = {}, []
        self._temporary = module.tempfile.TemporaryDirectory
        self._route_inputs()
        self._order_inputs()
        self._hidden_inputs()
        self._unknown_inputs()
        duplicate = self._duplicate_input()
        for name, raw in (
            ("EXAMPLE_syntax", b"{EXAMPLE_RELIABILITY"),
            ("EXAMPLE_duplicate", duplicate),
            ("EXAMPLE_utf8", bytes([255])),
        ):
            self._write(name, raw, {"kind": "raw", "status": "invalid"})
        self.assertEqual(len(self.inputs), CASES)
        for directory in self.producer_directories:
            directory.cleanup()

    def _duplicate_input(self) -> bytes:
        raw = Path(self.inputs["EXAMPLE_tiny"]["path"]).read_bytes()
        payload = json.loads(raw)
        self.assertIs(type(payload["version"]), int)
        self.assertEqual(payload["version"], 1)
        version = json.dumps(payload["version"]).encode("ascii")
        duplicate = b'{"version":' + version + b"," + raw[1:]
        self.assertTrue(json.loads(duplicate) == payload, "EXAMPLE reliability duplicate changed its valid wrapper")
        pairs = json.loads(duplicate, object_pairs_hook=list)
        self.assertEqual([value for key, value in pairs if key == "version"], [1, 1])
        return duplicate

    def _route_inputs(self) -> None:
        wrap = self.producer_fixture.RouteLedgerPreparationTest.wrap
        for tiny, name in ((True, "EXAMPLE_tiny"), (False, "EXAMPLE_full")):
            producer = self._producer(tiny=tiny)
            self._complete(producer)
            self._save(name, wrap(producer), "within-declared-limits")

    def _order_inputs(self) -> None:
        wrap = self.producer_fixture.RouteLedgerPreparationTest.wrap
        for late in (False, True):
            producer = self._producer(tiny=False, diamond=True)
            order = ["plan", "review", "validation", "synthesis"] if late else [
                "plan", "review", "synthesis", "validation",
            ]
            self._complete(producer, order)
            payload = wrap(producer)
            attempts = payload["ledger_snapshot"]["attempts"]
            child = attempts[producer.mapping["validation"]]
            dependency = attempts[producer.mapping["synthesis"]]
            self.assertTrue(dependency["created_at"] == child["created_at"], "EXAMPLE reliability creation timestamps differ")
            self.assertTrue(dependency["history"][-1]["at"] == child["created_at"], "EXAMPLE reliability completion timestamps differ")
            self.assertTrue(child["lineage"]["parent_attempt_id"] == producer.mapping["review"], "EXAMPLE reliability lineage differs")
            self._save("EXAMPLE_reversed_order" if late else "EXAMPLE_ordered",
                       payload, "invalid" if late else "within-declared-limits")

    def _hidden_inputs(self) -> None:
        wrap = self.producer_fixture.RouteLedgerPreparationTest.wrap
        for mode, status in (("completed", "unassessable"), ("overage", "over-budget")):
            producer = self._producer()
            self._complete(producer)
            mapping = dict(producer.mapping)
            producer.add(producer.prepared["nodes"][0], mode=mode, request_id="EXAMPLE_RELIABILITY_HIDDEN")
            producer.mapping = mapping
            self._save("EXAMPLE_hidden_" + mode, wrap(producer), status)

    def _unknown_inputs(self) -> None:
        module = self.producer_fixture
        wrap = module.RouteLedgerPreparationTest.wrap
        for unknown in ("projection", "tokens", "cost_microunits"):
            producer = self._producer()
            self._complete(producer)
            payload = wrap(producer)
            if unknown == "projection":
                payload["route_input"]["projection_policy"].update(
                    mode="unknown", tokens_per_utf8_byte_upper=None, input_overhead_tokens=None, billing=None,
                )
            else:
                payload["route_input"]["limits"][unknown] = None
            module.RouteLedgerPreparationTest.recontext(payload)
            self._save("EXAMPLE_unknown_" + unknown, payload, "unassessable")

    @staticmethod
    def _timeout_output(value):
        if value is None:
            return {"type": "absent", "bytes": None, "sha256": None}
        if type(value) is bytes:
            kind, raw = "bytes", value
        elif type(value) is str:
            kind, raw = "str", value.encode("utf-8", errors="surrogatepass")
        else:
            return {"type": "unsupported", "bytes": None, "sha256": None}
        return {"type": kind, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

    def _parent_call(self, phase, call, *args, **kwargs):
        try:
            return call(*args, **kwargs)
        except subprocess.TimeoutExpired as error:
            timeout = error.timeout
            if type(timeout) not in (int, float) or not 0 <= timeout <= 1_000_000:
                timeout = None
            note = {
                "phase": phase[:128], "type": "TimeoutExpired", "timeout_seconds": timeout,
                "stdout": self._timeout_output(error.stdout),
                "stderr": self._timeout_output(error.stderr),
            }
        raise self.failureException(PARENT_TIMEOUT_PREFIX + canonical(note)) from None

    def run_install(self, **extra_env: str) -> subprocess.CompletedProcess[str]:
        return self._parent_call(
            "install", subprocess.run,
            ["bash", str(self.source / "scripts/install.sh"),
             "--skills-dir", str(self.install.skills), "--yes"],
            cwd=self.install.tmp, env={**self.env, **extra_env},
            capture_output=True, text=True, check=False, timeout=180,
        )

    def run_checker(self) -> subprocess.CompletedProcess[str]:
        return self._parent_call(
            "installed-checker", self.install.run_checker,
            "--source-dir", str(self.source), "--installed-dir", str(self.install.target), "--check",
            source=self.source,
        )

    @staticmethod
    def _result_note(result) -> str:
        return json.dumps({
            "exit": result.returncode,
            "stdout_bytes": len(result.stdout.encode("utf-8")),
            "stdout_sha256": hashlib.sha256(result.stdout.encode("utf-8")).hexdigest(),
            "stderr_bytes": len(result.stderr.encode("utf-8")),
            "stderr_sha256": hashlib.sha256(result.stderr.encode("utf-8")).hexdigest(),
        }, sort_keys=True)

    def assert_image(self, target: Path, expected: dict) -> None:
        self.assertTrue(fixture.checker.build_manifest(target) == expected,
                        "EXAMPLE reliability complete projection differs")
        files = {item["path"]: item["sha256"] for item in expected["files"]}
        directories = {item["path"] for item in expected["entries"] if item["kind"] == "directory"}
        for name in files:
            directories.update(str(parent) for parent in Path(name).parents if str(parent) != ".")
        image = fixture.snapshot(target)
        self.assertTrue(set(image) == set(files) | directories | {RECORD},
                        "EXAMPLE reliability complete installed inventory differs")
        for name, (mode, digest) in image.items():
            self.assertTrue(stat.S_ISDIR(mode) if name in directories else stat.S_ISREG(mode),
                            "EXAMPLE reliability installed path type differs")
            if name in files:
                self.assertTrue(digest == files[name], "EXAMPLE reliability installed content differs")
        record = json.loads((target / RECORD).read_text(encoding="utf-8"))
        self.assertEqual((record["version"], record["status"]), (2, "current"))
        self.assertTrue(record["source_dir"] == str(self.source.resolve()),
                        "EXAMPLE reliability install source identity differs")
        self.assertTrue(record["projection"] == expected["projection"],
                        "EXAMPLE reliability projection identity differs")
        for key in ("source_content_sha256", "installed_content_sha256"):
            self.assertEqual(record[key], expected["content_sha256"])
        for key in ("source_file_count", "installed_file_count"):
            self.assertEqual(record[key], expected["file_count"])
        self.assertFalse((target / "tests").exists())

    def real_install(self) -> None:
        before = fixture.snapshot(self.source)
        result = self.run_install()
        self.assertEqual(result.returncode, 0, self._result_note(result))
        self.assertTrue(fixture.snapshot(self.source) == before == self.source_image,
                        "EXAMPLE reliability installation changed its private source")
        self.assert_image(self.install.target, self.expected)
        check = self.run_checker()
        self.assertEqual(check.returncode, 0, self._result_note(check))
        self.installations.append({
            "installer": json.loads(self._result_note(result)), "checker": json.loads(self._result_note(check)),
            "source_sha256": digest(before), "target_sha256": digest(fixture.snapshot(self.install.target)),
            "manifest_sha256": digest(self.expected),
        })

    def prepare_replacement(self) -> dict:
        before = fixture.snapshot(self.source)
        self.assertTrue(before == self.source_image, "EXAMPLE reliability private source changed")
        security = self.source / "SECURITY.md"
        security.write_bytes(security.read_bytes() + b"\nEXAMPLE disposable reliability replacement marker.\n")
        self.source_image = fixture.snapshot(self.source)
        self.assertTrue(before.keys() == self.source_image.keys(),
                        "EXAMPLE reliability source inventory changed")
        self.assertTrue({path for path in before if before[path] != self.source_image[path]} == {"SECURITY.md"},
                        "EXAMPLE reliability replacement changed another source path")
        replacement = fixture.checker.build_manifest(self.source)
        self.assertNotEqual(replacement["content_sha256"], self.expected["content_sha256"])
        self.assertTrue(
            fixture.checker.compare_manifests(self.expected, replacement)["changed_files"] == ["SECURITY.md"],
            "EXAMPLE reliability replacement changed another projected file",
        )
        return replacement

    def _image_identities(self):
        self.assert_image(self.install.target, self.expected)
        installed = fixture.checker.build_manifest(self.install.target)
        self.assertTrue(installed == self.expected, "EXAMPLE reliability complete manifest identity differs")
        return {
            "manifests": {
                "expected_sha256": digest(self.expected), "installed_sha256": digest(installed),
                "content_sha256": installed["content_sha256"], "file_count": installed["file_count"],
                "projection_sha256": installed["projection"]["sha256"],
            },
            "install_record": file_identity(self.install.target / RECORD),
            "security": file_identity(self.install.target / "SECURITY.md"),
        }

    def _input_identities(self):
        found = []
        for name, item in sorted(self.inputs.items()):
            path = Path(item["path"])
            self.assertEqual(path.parent, self.install.tmp / "inputs")
            self.assertTrue(str(path.resolve()) == item["path"], "EXAMPLE reliability declared path differs")
            identity = file_identity(path)
            self.assertEqual(identity["sha256"], item["sha256"])
            found.append({"name": name, **identity})
        self.assertEqual(len(found), CASES)
        return found

    def _source_identities(self):
        self.assertEqual(Path(__file__).resolve(), fixture.ROOT / "tests/test_installed_route_ledger_consumers.py")
        paths = (
            "tests/test_installed_route_ledger_consumers.py",
            "tests/test_install_projection.py", "tests/test_installed_numeric_rollback.py",
            "tests/test_route_ledger_reconciliation_preparation.py", "tests/test_route_feasibility_preparation.py",
            "tests/test_invocation_ledger.py", "tests/fixtures/route-feasibility-preparation.json",
            "scripts/prepare_route_ledger_reconciliation.py", "scripts/prepare_route_feasibility.py",
            "scripts/check_installed_skill.py", "scripts/cwo_core/invocation_ledger.py",
            "scripts/cwo_core/work_sizing.py", "scripts/cwo_core/native_authority.py",
            "policy/native-worker-execution.yaml",
        )
        return [file_identity(fixture.ROOT / name) for name in sorted(paths)]

    def _child_report(self, result):
        self.assertLessEqual(len(result.stdout.encode("utf-8")), MAX_EVIDENCE_BYTES, self._result_note(result))
        self.assertTrue(result.stdout.endswith("\n") and result.stdout.count("\n") == 1, self._result_note(result))
        try:
            report = json.loads(result.stdout)
        except ValueError:
            self.fail("EXAMPLE reliability child report is unavailable: " + self._result_note(result))
        self._assert_bounded(report)
        self.assertEqual(result.returncode, 0, self._result_note(result) + " " + canonical(report.get("failure")))
        self.assertTrue(result.stderr == "", self._result_note(result))
        return report

    def _validate_report(self, report, identities, inputs):
        self.assertIs(report["ok"], True)
        self.assertEqual((report["cases"], report["controls"]), (CASES, 21))
        self.assertEqual(len(report["effects"]), 18)
        self.assertTrue(all(type(value) is int and value == 0 for value in report["effects"].values()),
                        "EXAMPLE reliability consumer attempted a forbidden effect")
        expected_controls = {name: 3 if name == "read" else 2 if name == "write" else 1 for name in report["effects"]}
        self.assertTrue(report["control_effects"] == expected_controls, "EXAMPLE reliability guard counts differ")
        self.assertEqual(report["duplicate_controls"], 1)
        self.assertGreater(report["reads"]["installed"], 0)
        self.assertEqual(report["reads"]["input"], CASES)
        self.assertEqual(report["interpreter"], list(sys.version_info[:2]))
        evidence = report["evidence"]
        self.assertEqual((evidence["schema"], evidence["scenario"]), (EVIDENCE_SCHEMA, self.transition["scenario"]))
        self.assertTrue(evidence["inputs"] == inputs, "EXAMPLE reliability retained input identities differ")
        for key in ("manifests", "install_record", "security"):
            self.assertTrue(evidence[key] == identities[key], "EXAMPLE reliability retained image identity differs")
        self.assertEqual(evidence["interpreter"], {
            "executable": str(Path(sys.executable).resolve()),
            "version": list(sys.version_info[:3]), "implementation": sys.implementation.name,
        })
        self.assertIs(evidence["test_output_only"], True)
        self.assertTrue(all(value is False for value in evidence["authority"].values()), "EXAMPLE reliability authority differs")
        self.assertEqual(set(evidence["authority"]), set(self.producer_fixture.consumer.FALSE_FIELDS))
        self._validate_origins(evidence["origins"])
        self.assertEqual(report["origins"], len(evidence["origins"]))
        self._validate_outcomes(report)
        self._validate_sensitivity(report["duplicate_sensitivity"], evidence["outcomes"])

    def _validate_origins(self, origins):
        self.assertTrue(9 <= len(origins) <= 128, "EXAMPLE reliability origin count differs")
        names = [item["name"] for item in origins]
        self.assertEqual(names, sorted(set(names)))
        required = {"prepare_route_ledger_reconciliation", "prepare_route_feasibility", "check_installed_skill",
                    "cwo_core", "cwo_core.invocation_ledger", "cwo_core.work_sizing",
                    "cwo_core.native_authority", "cwo_core.local_invocation", "cwo_core.beads"}
        self.assertTrue(required <= set(names), "EXAMPLE reliability required origin is absent")
        files = {item["path"]: item["sha256"] for item in self.expected["files"]}
        for item in origins:
            name = item["name"]
            self.assertTrue(name in required or name.startswith("cwo_core."), "EXAMPLE reliability origin name differs")
            self.assertIs(type(item["package"]), bool)
            relative = "scripts/" + name.replace(".", "/")
            relative += "/__init__.py" if item["package"] else ".py"
            self.assertIn(relative, files)
            path = self.install.target / relative
            self.assertTrue(item == {"name": name, "package": item["package"], **file_identity(path)}, "EXAMPLE reliability origin identity differs")
            self.assertEqual(item["sha256"], files[relative])

    def _validate_outcomes(self, report):
        outcomes = report["evidence"]["outcomes"]
        self.assertEqual([row["name"] for row in outcomes], sorted(self.inputs))
        for row in outcomes:
            item = self.inputs[row["name"]]
            status, expected = item["status"], item["result_sha256"]
            self.assertEqual((row["status"], row["result_sha256"]), (status, expected))
            self.assertEqual(row["library"], {"status": status, "result_sha256": expected})
            code = {"within-declared-limits": 0, "invalid": 2, "unassessable": 1, "over-budget": 1}[status]
            self.assertEqual(row["cli"], {"status": status, "exit": code, "result_sha256": expected})
            self.assertEqual(row["consumer_calls"]["main"], 1)
            self.assertEqual(row["consumer_calls"]["_decode"], 1)
            self.assertEqual(row["consumer_calls"]["prepare"], 2 if item["kind"] == "wrapper" else 1)
        for key in ("producer_calls", "consumer_calls"):
            totals = {name: sum(row[key][name] for row in outcomes) for name in report[key]}
            self.assertEqual(report[key], totals)
        for count in report["producer_calls"].values():
            self.assertGreater(count, 0)
        self.assertGreater(report["consumer_calls"]["_pairs"], 0)

    def _validate_sensitivity(self, record, outcomes):
        actual = {row["name"]: row for row in outcomes}
        self.assertEqual((record["case"], record["positive"]), ("EXAMPLE_duplicate", "EXAMPLE_tiny"))
        self.assertEqual((record["test_failure"], record["phase"]), ("AssertionError", "consumer-EXAMPLE_duplicate"))
        self.assertEqual(record["strict_result_sha256"], actual["EXAMPLE_duplicate"]["result_sha256"])
        self.assertEqual(record["permissive_result_sha256"], actual["EXAMPLE_tiny"]["result_sha256"])
        self.assertEqual(record["cli_exit"], 0)
        self.assertEqual(record["consumer_calls"], {"prepare": 3, "main": 2, "_decode": 2, "_pairs": 0})
        self.assertEqual((record["producer_calls"]["planner"], record["producer_calls"]["validator"]), (2, 2))
        self.assertGreater(record["producer_calls"]["charge"], 0)

    def _validate_transition(self):
        expected = {
            "fresh": ("fresh", "installed", 1),
            "replacement": ("replacement", "replaced", 2),
            "activation-rollback": ("activation-rollback", "restored", 1),
            "term-rollback": ("term-rollback", "restored", 1),
        }[self.scenario]
        record = self.transition
        self.assertEqual((record["scenario"], record["status"], len(self.installations)), expected)
        self.assertEqual(record["leftovers"], len(self.install.leftovers()))
        if record["scenario"] == "replacement":
            self.assertEqual(record["previous_sha256"], record["backup"]["sha256"])
            self.assertEqual(record["stages"], 0)
        if record["status"] == "restored":
            self._validate_rollback_record(record)

    def _validate_rollback_record(self, record):
        self.assertEqual(record["previous_sha256"], record["restored_sha256"])
        self.assertEqual(record["source_before_sha256"], record["source_after_sha256"])
        self.assertEqual(record["replacement_manifest_sha256"], record["witness_manifest_sha256"])
        self.assertNotEqual(record["replacement_manifest_sha256"], digest(self.expected))
        self.assertTrue(record["stage_absent"] and record["backup_absent"], "EXAMPLE reliability rollback paths remain")
        if record["scenario"] == "term-rollback":
            self.assertEqual(record["installer"]["exit"], 143)
        else:
            self.assertEqual(record["scenario"], "activation-rollback")
            self.assertNotEqual(record["installer"]["exit"], 0)

    def _assert_bounded(self, value, depth=0):
        self.assertLessEqual(depth, 16)
        if type(value) is dict:
            self.assertLessEqual(len(value), 128)
            for key, child in value.items():
                self.assertIs(type(key), str)
                self.assertLessEqual(len(key), 128)
                self._assert_bounded(child, depth + 1)
        elif type(value) is list:
            self.assertLessEqual(len(value), 128)
            for child in value:
                self._assert_bounded(child, depth + 1)
        elif type(value) is str:
            self.assertLessEqual(len(value), 1024)
        elif type(value) is int:
            self.assertTrue(0 <= value <= 1_000_000, "EXAMPLE reliability evidence count exceeds its bound")
        else:
            self.assertTrue(value is None or type(value) is bool, "EXAMPLE reliability evidence type differs")

    def _lifecycle_metadata(self):
        return {"transition": self.transition, "installations": self.installations,
                "source_image": self.source_image}

    def _retain_evidence(self, report, result, before, after, sources, row=None):
        metadata = self._lifecycle_metadata() if row is None else row["metadata"]
        transition = metadata["transition"]
        outcome = {
            "transition": transition,
            "installations": metadata["installations"],
            "source_sha256": digest(metadata["source_image"]),
            "private_before_sha256": digest(before),
            "private_after_sha256": digest(after), "source_removed": not self.source.exists(),
            "consumer_report_sha256": digest(report),
        }
        record = {
            **report["evidence"],
            "scenario": transition["scenario"],
            "shared_product_flow_sha256": digest(report),
            "shared_product_flow_scenario": report["evidence"]["scenario"],
            **{name: report[name] for name in (
                "effects", "controls", "control_effects", "producer_calls", "consumer_calls", "reads",
                "duplicate_controls", "duplicate_sensitivity",
            )},
            "sources": sources, "probe_sha256": hashlib.sha256(PROBE.encode("utf-8")).hexdigest(),
            "child": json.loads(self._result_note(result)),
            "scenario_outcome": outcome, "scenario_outcome_sha256": digest(outcome),
            "rollback_outcome_sha256": digest(transition) if transition["status"] == "restored" else None,
        }
        record["record_sha256"] = digest(record)
        self._assert_bounded(record)
        encoded = canonical(record)
        self.assertLessEqual(len(encoded.encode("ascii")), MAX_EVIDENCE_BYTES)
        print(EVIDENCE_PREFIX + encoded, flush=True)

    def consume_without_source(self, rows=None) -> None:
        self.assertTrue(fixture.snapshot(self.source) == self.source_image,
                        "EXAMPLE reliability private source changed before removal")
        self.assertEqual(self.source, self.install.tmp / "source")
        self.assertNotEqual(self.source.resolve(), fixture.ROOT.resolve())
        self._validate_transition()
        identities, inputs = self._image_identities(), self._input_identities()
        sources = self._source_identities()
        shutil.rmtree(self.source)
        self.assertFalse(self.source.exists())
        before = fixture.snapshot(self.install.tmp)
        result = self._parent_call(
            "installed-consumer", subprocess.run,
            [sys.executable, "-I", "-B", "-c", PROBE, str(self.install.target),
             str(fixture.ROOT.resolve()), str(self.source), str(self.install.tmp)],
            cwd=self.install.tmp / "home", env=self.env,
            input=json.dumps({"manifest": self.expected, "inputs": self.inputs,
                              "scenario": self.transition["scenario"]}),
            capture_output=True, text=True, check=False, timeout=60,
        )
        after = fixture.snapshot(self.install.tmp)
        self.assertTrue(after == before,
                        "EXAMPLE reliability consumer changed a private path")
        report = self._child_report(result)
        self.assertTrue(self._image_identities() == identities, "EXAMPLE reliability observed image identity changed")
        self.assertTrue(self._input_identities() == inputs, "EXAMPLE reliability observed input identity changed")
        self._validate_report(report, identities, inputs)
        for row in rows or [None]:
            self._retain_evidence(report, result, before, after, sources, row)

    def test_installed_route_ledger_lifecycle_without_source(self) -> None:
        self.assertEqual(len(self.install.leftovers()), 0)
        self._validate_transition()
        shared = RestoredInstalledRows(self, self._lifecycle_metadata)
        shared.exercise_rollbacks()
        shared.retain()
        with self.subTest(rows=("fresh", "activation-rollback", "term-rollback")):
            self.consume_without_source(rows=shared.rows)


    def rollback(self, mode: str) -> None:
        self.scenario = mode + "-rollback"
        previous = fixture.snapshot(self.install.target)
        replacement = self.prepare_replacement()
        source_before = fixture.snapshot(self.source)
        witness = self.install.tmp / ("EXAMPLE_RELIABILITY_WITNESS_" + mode)
        event = self.install.tmp / ("EXAMPLE_RELIABILITY_EVENT_" + mode)
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
            self.assertEqual(result.returncode, 143, self._result_note(result))
        else:
            self.assertNotEqual(result.returncode, 0, self._result_note(result))
            self.assertTrue(
                f"error: could not activate staged install at {self.install.target}" in result.stderr.splitlines(),
                "EXAMPLE reliability activation failure result differs",
            )
        self.assertTrue(
            f"Restored the previous install at {self.install.target}" in result.stderr.splitlines(),
            "EXAMPLE reliability rollback result is absent",
        )
        self.assertTrue(fixture.snapshot(self.install.target) == previous,
                        "EXAMPLE reliability restored image differs")
        self.assertTrue(fixture.snapshot(self.source) == source_before == self.source_image,
                        "EXAMPLE reliability rollback changed its source")
        self.assertEqual(len(self.install.leftovers()), 0)
        stage, backup = (Path(line) for line in event.read_text(encoding="utf-8").splitlines())
        self.assertEqual(stage.parent, self.install.skills)
        self.assertTrue(stage.name.startswith(f".{fixture.SKILL}.stage."))
        self.assertEqual(backup.parent, self.install.backups)
        self.assertTrue(backup.name.startswith(f"{fixture.SKILL}.prev."))
        self.assert_image(witness, replacement)
        self.assert_image(self.install.target, self.expected)
        self.transition = {
            "scenario": mode + "-rollback", "status": "restored", "leftovers": len(self.install.leftovers()),
            "installer": json.loads(self._result_note(result)),
            "previous_sha256": digest(previous),
            "restored_sha256": digest(fixture.snapshot(self.install.target)),
            "source_before_sha256": digest(source_before),
            "source_after_sha256": digest(fixture.snapshot(self.source)),
            "replacement_manifest_sha256": digest(replacement),
            "witness_manifest_sha256": digest(fixture.checker.build_manifest(witness)),
            "witness_sha256": digest(fixture.snapshot(witness)),
            "event": file_identity(event),
            "stage": str(stage.resolve()), "backup": str(backup.resolve()),
            "stage_absent": not stage.exists(), "backup_absent": not backup.exists(),
        }
        shutil.rmtree(witness)
        self._validate_transition()

    def test_replacement_installed_route_ledger_without_source(self) -> None:
        self.scenario = "replacement"
        previous = fixture.snapshot(self.install.target)
        self.expected = self.prepare_replacement()
        self.real_install()
        backups = list(self.install.backups.glob(f"{fixture.SKILL}.prev.*"))
        self.assertEqual(len(backups), 1)
        self.assertTrue(fixture.snapshot(backups[0]) == previous, "EXAMPLE reliability backup differs")
        self.assertEqual(len(list(self.install.skills.glob(f".{fixture.SKILL}.stage.*"))), 0)
        self.transition = {
            "scenario": "replacement", "status": "replaced",
            "previous_sha256": digest(previous),
            "backup": {"path": str(backups[0].resolve()), "sha256": digest(fixture.snapshot(backups[0]))},
            "stages": len(list(self.install.skills.glob(f".{fixture.SKILL}.stage.*"))),
            "leftovers": len(self.install.leftovers()),
        }
        self.consume_without_source()


class ParentTimeoutReportingTests(unittest.TestCase):
    def _assert_timeout(self, entry, phase, seconds, stdout, stderr):
        case = InstalledRouteLedgerConsumerTests("test_installed_route_ledger_lifecycle_without_source")
        case.fixture_variant = "ordinary"
        command_marker = "EXAMPLE_RELIABILITY_PRIVATE_COMMAND"
        output_marker = "EXAMPLE_RELIABILITY_PRIVATE_OUTPUT"
        timeout = subprocess.TimeoutExpired([command_marker], seconds, output=stdout, stderr=stderr)
        caught, output, result = [], io.StringIO(), unittest.TestResult()

        def exercise():
            with patch.object(subprocess, "run", side_effect=timeout):
                try:
                    getattr(case, entry)()
                except case.failureException as failure:
                    caught.append(failure)
                    raise

        with (
            patch.object(case, case._testMethodName, exercise),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(output),
        ):
            case.run(result)
        self.assertFalse(result.wasSuccessful(), "EXAMPLE reliability timeout was accepted")
        self.assertEqual((len(result.failures), len(result.errors)), (1, 0),
                         "EXAMPLE reliability timeout did not remain a unittest failure")
        self.assertEqual(len(caught), 1, "EXAMPLE reliability parent timeout was not reached")
        failure = caught[0]
        self.assertIsNone(failure.__cause__)
        self.assertIsNone(failure.__context__)
        self.assertTrue(failure.__suppress_context__)
        self.assertEqual(len(failure.args), 1)
        message = failure.args[0]
        self.assertIs(type(message), str)
        self.assertLessEqual(len(message.encode("ascii")), 1024)
        self.assertTrue(message.startswith(PARENT_TIMEOUT_PREFIX),
                        "EXAMPLE reliability timeout phase record is absent")
        record = json.loads(message[len(PARENT_TIMEOUT_PREFIX):])
        self.assertEqual(set(record), {"phase", "type", "timeout_seconds", "stdout", "stderr"})
        self.assertEqual((record["phase"], record["type"], record["timeout_seconds"]),
                         (phase, "TimeoutExpired", seconds))
        self._assert_timeout_output(record["stdout"], stdout)
        self._assert_timeout_output(record["stderr"], stderr)
        rendered = ("".join(traceback.format_exception(failure))
                    + result.failures[0][1] + output.getvalue())
        for marker in (command_marker, output_marker, EVIDENCE_PREFIX, PROBE):
            self.assertTrue(marker not in rendered,
                            "EXAMPLE reliability timeout disclosed private data or success evidence")
        self.assertEqual(output.getvalue(), "")

    def _assert_timeout_output(self, record, value):
        self.assertEqual(set(record), {"type", "bytes", "sha256"})
        if value is None:
            self.assertEqual(record, {"type": "absent", "bytes": None, "sha256": None})
            return
        raw = value.encode("utf-8", errors="surrogatepass") if type(value) is str else value
        self.assertEqual(record["type"], "str" if type(value) is str else "bytes")
        self.assertEqual(record["bytes"], len(raw))
        self.assertEqual(record["sha256"], hashlib.sha256(raw).hexdigest())

    def test_installer_timeout_is_a_bounded_failure(self):
        self._assert_timeout(
            "run_install", "install", 180,
            b"EXAMPLE_RELIABILITY_PRIVATE_OUTPUT", "EXAMPLE_RELIABILITY_PRIVATE_OUTPUT",
        )

    def test_checker_timeout_is_a_bounded_failure(self):
        self._assert_timeout("run_checker", "installed-checker", 300, None, None)

    def test_installed_consumer_timeout_is_a_bounded_failure(self):
        self._assert_timeout(
            "consume_without_source", "installed-consumer", 60,
            "EXAMPLE_RELIABILITY_PRIVATE_OUTPUT", b"EXAMPLE_RELIABILITY_PRIVATE_OUTPUT",
        )


if __name__ == "__main__":
    unittest.main()
