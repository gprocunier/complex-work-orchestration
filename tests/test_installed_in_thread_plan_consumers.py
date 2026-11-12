"""Retain bounded reliability observations from disposable installed proposal consumers."""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from collections import Counter

from tests.installed_consumer_fixtures import RestoredInstalledRows, prepare_replacement
from tests import test_install_projection as fixture
from tests import test_in_thread_plan_preparation as producer
from tests.test_installed_numeric_rollback import MV_SHIM

RECORD = ".cwo-install-manifest.json"
SCHEMA = "cwo-installed-in-thread-consumer-evidence-v1"
PREFIX = "CWO_INSTALLED_IN_THREAD_EVIDENCE "
FALSE_FIELDS = (
    "operative", "qualified", "effect_authority", "production_ready",
    "minimal_tier_available", "successful_closure_available",
    "candidate_current_authenticated", "baseline_custody_authenticated",
)
BASE_EFFECTS = (
    "read", "write", "mutation", "process-audit", "network-audit",
    "process-run", "process-Popen", "process-system", "socket-call",
    "socket-connect", "urlopen", "http-request", "temporary-directory", "temporary-file",
)
NAMED_EFFECTS = (
    "capture-candidate", "verify-candidate", "capture-workspace",
    "beads-run", "beads-structured", "beads-create", "beads-link",
)
WATCHED_CALLS = (
    "cwo_core.requirement_baseline.baseline_errors",
    "cwo_core.requirement_baseline.resolve_chain",
    "cwo_core.candidate_identity.candidate_errors",
    "cwo_core.candidate_identity.baseline_binding_errors",
    "cwo_core.routing.classify_work",
)


import io
import tempfile
import traceback
from unittest.mock import patch
def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def identity(path):
    path = Path(path).resolve()
    data = canonical(sorted(os.listdir(path))) if path.is_dir() else path.read_bytes()
    return {"path": str(path), "sha256": digest(data)}


def output_summary(value):
    data = value if isinstance(value, bytes) else str(value or "").encode("utf-8", errors="replace")
    return {"bytes": len(data), "sha256": digest(data)}


def bounded_run(phase, command, **kwargs):
    try:
        return subprocess.run(command, capture_output=True, check=False, timeout=kwargs.pop("timeout", 180), **kwargs)
    except subprocess.TimeoutExpired as error:
        diagnostic = {
            "status": "timeout", "phase": phase,
            "stdout": output_summary(error.stdout), "stderr": output_summary(error.stderr),
        }
        raise AssertionError(json.dumps(diagnostic, sort_keys=True)) from None


def retain(record, stream):
    stream.write(PREFIX + json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    stream.flush()


def observation_totals(outcomes):
    totals = {side: {field: Counter() for field in ("validator_calls", "routing_inputs")}
              for side in ("helper", "oracle")}
    for outcome in outcomes:
        if "helper_observation" not in outcome:
            continue
        groups = {"helper": [outcome["helper_observation"]],
                  "oracle": list(outcome["oracle_observations"].values())}
        for side, rows in groups.items():
            for row in rows:
                for field in ("validator_calls", "routing_inputs"):
                    totals[side][field].update(row[field])
    return {side: {field: dict(counts) for field, counts in values.items()} for side, values in totals.items()}


def normalized_observation(report):
    inventories = ("inputs", "origins", "outcomes", "reads", "cache_refusals")
    return {
        **{key: value for key, value in report.items() if key not in inventories},
        "inventories": {key: {"count": len(report[key]), "sha256": digest(report[key])} for key in inventories},
        "api_totals": observation_totals(report["outcomes"]),
    }


PROBE = r'''
import contextlib
import hashlib
import http.client
import importlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import urllib.request
from collections import Counter
from unittest.mock import patch

root, checkout, source, area, input_path = (Path(item).resolve() for item in sys.argv[1:6])
scripts, library = root / "scripts", Path(os.__file__).resolve().parent
assert sys.flags.isolated and sys.dont_write_bytecode
assert Path.cwd() == area / "home" == Path(os.environ["HOME"]).resolve()
assert source == area / "source" and not source.exists()
assert root.is_relative_to(area) and not area.is_relative_to(checkout)
assert not any(name == "tests" or name.startswith(("tests.", "cwo_core")) for name in sys.modules)
assert "prepare_in_thread_plan" not in sys.modules
sys.path[:] = [str(scripts)] + [
    item for item in sys.path if Path(item).is_dir()
    and Path(item).resolve().is_relative_to(library)
    and not {"site-packages", "dist-packages"} & set(Path(item).parts)
]
phase, reads, cache_attempts, descriptors, opening = "inputs", set(), set(), {}, []
effects, calls, route_inputs = Counter(), Counter(), []
installed_paths, registered = set(), set()
named = {
    ("cwo_core.candidate_identity", "capture_candidate"): "capture-candidate",
    ("cwo_core.candidate_identity", "verify_candidate"): "verify-candidate",
    ("cwo_core.workspace_capture", "capture"): "capture-workspace",
    ("cwo_core.beads", "run_bd"): "beads-run",
    ("cwo_core.beads", "run_bd_structured"): "beads-structured",
    ("cwo_core.beads", "create_bead"): "beads-create",
    ("cwo_core.beads", "add_dependency"): "beads-link",
}
watched = {
    ("cwo_core.requirement_baseline", "baseline_errors"),
    ("cwo_core.requirement_baseline", "resolve_chain"),
    ("cwo_core.candidate_identity", "candidate_errors"),
    ("cwo_core.candidate_identity", "baseline_binding_errors"),
    ("cwo_core.routing", "classify_work"),
}
false_fields = (
    "operative", "qualified", "effect_authority", "production_ready",
    "minimal_tier_available", "successful_closure_available",
    "candidate_current_authenticated", "baseline_custody_authenticated",
)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")

def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()

def identity(path):
    path = Path(path).resolve()
    data = canonical(sorted(os.listdir(path))) if path.is_dir() else path.read_bytes()
    return {"path": str(path), "sha256": digest(data)}

class EffectRefused(BaseException):
    pass

def block(name):
    effects[name] += 1
    raise EffectRefused(name)

observed_names = {key[1] for key in named} | {key[1] for key in watched}

def profile(frame, event, arg):
    if event != "call" or frame.f_code.co_name not in observed_names:
        return
    key = (frame.f_globals.get("__name__"), frame.f_code.co_name)
    if key in named:
        block(named[key])
    if key in watched:
        calls[".".join(key)] += 1
    if key == ("cwo_core.routing", "classify_work"):
        fields = ("text", "text_segments", "file_paths", "requested_roles", "data_sensitivity")
        fields += ("share_boundary", "external_ok", "local_ok", "prefer_local",
                   "allow_disclosure_escalation", "current_authority", "operative_evaluated_at")
        route_inputs.append(digest({name: frame.f_locals[name] for name in fields}))

def path_for(value, directory=None):
    if isinstance(value, int):
        return descriptors[value]
    path = Path(os.fsdecode(value))
    if directory not in (None, -1) and not path.is_absolute():
        path = path_for(directory) / path
    return path.resolve()

def read_path(path):
    if path.suffix == ".pyc" and (path.is_relative_to(root) or not path.exists()):
        cache_attempts.add(str(path))
        raise FileNotFoundError("EXAMPLE cached reliability input is unavailable.")
    allowed = path == input_path or path in installed_paths
    allowed |= path.is_relative_to(library) and not {"site-packages", "dist-packages"} & set(path.parts)
    if not allowed:
        block("read")
    if phase == "calls" and path.parent in (root / "policy", root / "schemas") and path not in registered:
        block("read")
    reads.add(str(path))

def audit(event, args):
    if event == "open":
        path = opening[-1] if opening else path_for(args[0])
        if (args[2] or 0) & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            block("write")
        read_path(path)
    elif event in {"os.listdir", "os.scandir"}:
        read_path(path_for(args[0]))
    elif event in {"os.remove", "os.rmdir", "os.mkdir", "os.rename", "os.link", "os.symlink",
                   "os.chmod", "os.chown", "os.truncate", "os.utime"}:
        block("mutation")
    elif event in {"subprocess.Popen", "os.system", "os.exec", "os.spawn", "os.posix_spawn",
                   "os.fork", "os.forkpty"}:
        block("process-audit")
    elif event.startswith("socket."):
        block("network-audit")

real_open = os.open
def open_path(path, flags, *args, **kwargs):
    resolved = path_for(path, kwargs.get("dir_fd"))
    opening.append(resolved)
    try:
        descriptor = real_open(path, flags, *args, **kwargs)
    finally:
        opening.pop()
    descriptors[descriptor] = resolved
    return descriptor

def guard(name):
    return lambda *args, **kwargs: block(name)

sys.addaudithook(audit)
sys.setprofile(profile)
payload = json.loads(input_path.read_bytes())
assert digest(input_path.read_bytes()) == sys.argv[6]
expected, mode = payload["manifest"], payload["mode"]
installed_paths = {root / item["path"] for item in expected["files"]} | {root / ".cwo-install-manifest.json", root}
installed_paths.update(parent for path in list(installed_paths) for parent in path.parents if parent.is_relative_to(root))
installed_paths.update(root / item["path"] for item in expected["entries"])
registered = {root / "policy" / name for name in payload["policy_names"]}
registered.update(root / "schemas" / name for name in payload["schema_names"].values())
outcomes, bindings = [], {}

def held(result):
    assert all(result[field] is False for field in false_fields)
    assert type(result["open_requirements"]) is list
    assert all(type(message) is str for message in result["open_requirements"])
    assert "Full production closure qualification remains open." in result["open_requirements"]
    assert "In-thread plan activation remains open." in result["open_requirements"]
    assert type(result["errors"]) is list
    assert all(type(message) is str and message.strip() for message in result["errors"])
    assert len(canonical(result["errors"])) <= 64 * 1024
    if result["status"] != "proposed-in-thread":
        assert result["shape"] is None and result["nodes"] == [] and result["errors"]

def graph(result):
    criteria = result["baseline_chain"]["baseline"]["criteria"]
    required = [item["id"] for item in criteria if item["applicability"] == "required"]
    nodes = result["nodes"]
    assert Counter(item for node in nodes for item in node["criterion_ids"]) == Counter(required)
    assert {item["criterion_id"] for item in result["applicability"]} == {item["id"] for item in criteria}
    seen, ancestors = set(), {}
    for node in nodes:
        assert set(node) == {"id", "kind", "depends_on", "criterion_ids", "obligation"}
        assert type(node["criterion_ids"]) is list and type(node["depends_on"]) is list
        assert node["id"] not in seen and set(node["depends_on"]) <= seen
        ancestors[node["id"]] = set(node["depends_on"])
        for dependency in node["depends_on"]:
            ancestors[node["id"]].update(ancestors[dependency])
        if node["kind"] in {"obligation", "review", "disclosure", "report"}:
            assert "content" in ancestors[node["id"]]
        assert node["kind"] not in {"worker", "dispatch", "admission", "paid-review"}
        assert "status" not in node
        seen.add(node["id"])
    assert {"content", "adjudication", "disclosure", "report"} <= seen

def classify(task):
    return routing.classify_work(
        task["text"], text_segments=task["text_segments"], file_paths=task["file_paths"],
        requested_roles=task["requested_roles"], data_sensitivity=task["data_sensitivity"],
        share_boundary="no-outside-sharing", external_ok=False, local_ok=False, prefer_local=False,
        allow_disclosure_escalation=False, current_authority=None,
        operative_evaluated_at="2000-01-01T00:00:00Z",
    )

def observe(call):
    prior_calls, start = calls.copy(), len(route_inputs)
    value = call()
    observation = {
        "validator_calls": {".".join(key): calls[".".join(key)] - prior_calls[".".join(key)]
                            for key in sorted(watched)},
        "routing_inputs": dict(Counter(route_inputs[start:])),
    }
    return value, observation

def assert_api_observation(result, observation):
    if result["status"] != "refused":
        assert all(observation["validator_calls"][".".join(key)] > 0 for key in watched), (
            "EXAMPLE reliability API observations are incomplete.")
        assert sum(observation["routing_inputs"].values()) == 1

def save(name, result, code=None, *, helper_observation, oracle_observations=None):
    held(result)
    outcomes.append({
        "name": name, "status": result["status"], "exit_code": code,
        "result_sha256": digest(result), "errors_sha256": digest(result["errors"]),
        "helper_observation": helper_observation, "oracle_observations": oracle_observations or {},
    })

def exercise(case):
    request, before = case["request"], canonical(case["request"])
    raw, output = canonical(request), io.StringIO()
    results, observations = [], []
    for suffix, invoke in (
        ("library", lambda: preview.prepare_proposal(request)),
        ("json", lambda: preview.prepare_json(raw)),
        ("main", lambda: preview.main([], stdin=io.BytesIO(raw), stdout=output)),
    ):
        value, observation = observe(invoke)
        if suffix == "main":
            code, value = value, json.loads(output.getvalue())
        assert_api_observation(value, observation)
        results.append(value)
        observations.append(observation)
    assert results[1] == results[2]
    if case["name"] == "version-2":
        assert type(request["version"]) is float and request["version"] == 1.0
        assert case["status"] == "refused"
        assert results[0]["errors"] == ["Input contains an unsupported JSON type."]
        assert results[1]["errors"] == ["JSON floats and nonfinite numbers are unsupported."]
        assert {key: value for key, value in results[0].items() if key != "errors"} == {
            key: value for key, value in results[1].items() if key != "errors"
        }
    else:
        assert results[0] == results[1]
    assert all(result["status"] == case["status"] for result in results)
    assert canonical(request) == before
    assert code == (0 if case["status"] == "proposed-in-thread" else 1)
    result = results[0]
    oracles = {}
    if result["status"] != "refused":
        assert result["candidate"] == request["candidate"] and result["task_context"] == request["task"]
        chain, oracles["baseline"] = observe(
            lambda: rb.resolve_chain(request["baseline"], request["amendments"]))
        route, oracles["routing"] = observe(lambda: classify(request["task"]))
        assert result["baseline_chain"] == chain
        assert result["routing_recommendation"] == route
        expected_routes = oracles["routing"]["routing_inputs"]
        assert sum(expected_routes.values()) == 1
        assert all(observation["routing_inputs"] == expected_routes for observation in observations)
    for suffix, item, observation in zip(("library", "json", "main"), results, observations):
        save(case["name"] + ":" + suffix, item, code if suffix == "main" else None,
             helper_observation=observation, oracle_observations=oracles if suffix == "library" else None)
    for index in case.get("unknown", []):
        assert f"Requested role at index {index} is not registered in the real expert registry." in result["errors"]
    if case.get("gate"):
        assert result["routing_recommendation"][case["gate"]] is True
        assert f"Policy obligation {case['gate']} remains required or unresolved." in result["errors"]
    if case.get("features"):
        assert result["routing_recommendation"]["risk_assessment"]["features"]
    if result["status"] == "proposed-in-thread":
        graph(result)
        if case.get("binding_change"):
            assert result["proposal_binding"] != bindings["documentation"]
        bindings[case["name"]] = result["proposal_binding"]

def exercise_raw():
    for case in payload["raw"]:
        raw, output = bytes(case["octets"]), io.StringIO()
        result, json_observation = observe(lambda: preview.prepare_json(raw))
        assert_api_observation(result, json_observation)
        code, main_observation = observe(
            lambda: preview.main([], stdin=io.BytesIO(raw), stdout=output))
        main_result = json.loads(output.getvalue())
        assert_api_observation(main_result, main_observation)
        assert result == main_result and result["status"] == case["status"]
        assert code == (0 if case["status"] == "proposed-in-thread" else 1)
        if case["name"] == "duplicate":
            assert json.loads(raw) == payload["cases"][0]["request"]
            assert "JSON contains duplicate object keys." in result["errors"]
        if case["name"] == "valid":
            assert digest(result) == outcomes[0]["result_sha256"]
        save("raw-" + case["name"] + ":json", result, helper_observation=json_observation)
        save("raw-" + case["name"] + ":main", result, code, helper_observation=main_observation)
    for argument in ("--help", "--minimal"):
        output = io.StringIO()
        code, observation = observe(lambda: preview.main([argument], stdin=io.BytesIO(b""), stdout=output))
        result = json.loads(output.getvalue())
        assert_api_observation(result, observation)
        assert code == 1 and result["status"] == "refused"
        save("argument-" + argument, result, code, helper_observation=observation)

def origins():
    rows = []
    for name, module in sorted(list(sys.modules.items())):
        if not (name == "cwo_core" or name.startswith("cwo_core.") or name in {"prepare_in_thread_plan", "check_installed_skill"}):
            continue
        package = module.__spec__.submodule_search_locations is not None
        path = scripts / name.replace(".", "/")
        path = path / "__init__.py" if package else path.with_suffix(".py")
        assert Path(module.__file__).resolve() == Path(module.__spec__.origin).resolve() == path
        locations = [str(Path(item).resolve()) for item in module.__spec__.submodule_search_locations or []]
        if package:
            assert [Path(item).resolve() for item in module.__path__] == [path.parent]
            assert locations == [str(path.parent)]
        assert str(path) in reads
        rows.append({**identity(path), "module": name, "spec": str(path), "package_paths": locations})
    assert not any(name == "tests" or name.startswith("tests.") for name in sys.modules)
    assert "scaffold_workgraph" not in sys.modules
    return rows

def named_controls(ci, workspace, beads):
    return [
        ("capture-candidate", lambda: ci.capture_candidate("EXAMPLE", chain={}, base_commit="EXAMPLE", scope_paths=[])),
        ("verify-candidate", lambda: ci.verify_candidate({}, "EXAMPLE")),
        ("capture-workspace", lambda: workspace.capture(
            "EXAMPLE", max_files=1, max_bytes=1, max_seconds=1, max_entries=1)),
        ("beads-run", lambda: beads.run_bd(["EXAMPLE"])),
        ("beads-structured", lambda: beads.run_bd_structured(
            ["EXAMPLE"], directory="EXAMPLE", database="EXAMPLE", actor="EXAMPLE")),
        ("beads-create", lambda: beads.create_bead("EXAMPLE")),
        ("beads-link", lambda: beads.add_dependency("EXAMPLE-first", "EXAMPLE-last")),
    ]

def controls(full):
    probes = [
        ("read", lambda: open(checkout / "EXAMPLE_BLOCKED", "rb")),
        ("read", lambda: open(source / "EXAMPLE_BLOCKED", "rb")),
        ("read", lambda: open(input_path.with_name("EXAMPLE_UNDECLARED"), "rb")),
        ("read", lambda: open(root / "policy/EXAMPLE-undeclared.yaml", "rb")),
        ("read", lambda: open(root / "schemas/EXAMPLE-undeclared.schema.json", "rb")),
        ("write", lambda: open(root / "EXAMPLE_BLOCKED", "wb")),
        ("mutation", lambda: os.mkdir(area / "EXAMPLE_BLOCKED")),
        ("process-run", lambda: subprocess.run(["EXAMPLE_NEVER_RUN"])),
        ("process-Popen", lambda: subprocess.Popen(["EXAMPLE_NEVER_RUN"])),
        ("process-system", lambda: os.system("EXAMPLE_NEVER_RUN")),
        ("process-audit", lambda: sys.audit("subprocess.Popen", None, None, None, None)),
        ("network-audit", lambda: sys.audit("socket.__new__", None, None, None, None)),
        ("socket-call", lambda: socket.socket()),
        ("socket-connect", lambda: socket.create_connection(("EXAMPLE.invalid", 1))),
        ("urlopen", lambda: urllib.request.urlopen("https://EXAMPLE.invalid")),
        ("http-request", lambda: http.client.HTTPConnection.request(None, "GET", "/EXAMPLE")),
        ("temporary-directory", lambda: tempfile.TemporaryDirectory()),
        ("temporary-file", lambda: tempfile.NamedTemporaryFile()),
    ]
    if full:
        ci, workspace, beads = (sys.modules[name] for name in (
            "cwo_core.candidate_identity", "cwo_core.workspace_capture", "cwo_core.beads"))
        probes += named_controls(ci, workspace, beads)
    counts = Counter()
    for name, call in probes:
        before = effects.copy()
        try:
            call()
        except EffectRefused as error:
            assert error.args == (name,)
        else:
            raise AssertionError("EXAMPLE reliability guard missed its positive control.")
        finally:
            sys.setprofile(profile)
        before[name] += 1
        assert effects == before
        counts[name] += 1
    return dict(counts)

failure, image, origin_rows, control_counts = None, None, [], {}
full = mode not in {"missing-module", "inventory"}
with contextlib.ExitStack() as stack:
    for target, name in (
        ("subprocess.run", "process-run"), ("subprocess.Popen", "process-Popen"),
        ("os.system", "process-system"), ("socket.socket", "socket-call"),
        ("socket.create_connection", "socket-connect"), ("urllib.request.urlopen", "urlopen"),
        ("http.client.HTTPConnection.request", "http-request"),
        ("tempfile.TemporaryDirectory", "temporary-directory"),
        ("tempfile.NamedTemporaryFile", "temporary-file"),
    ):
        stack.enter_context(patch(target, guard(name)))
    stack.enter_context(patch("os.open", open_path))
    try:
        phase = "manifest"
        checker = importlib.import_module("check_installed_skill")
        actual = checker.build_manifest(root, strict=False)
        image = {
            "expected_sha256": digest(expected), "installed_sha256": digest(actual),
            "content_sha256": actual["content_sha256"], "file_count": actual["file_count"],
            "projection_sha256": actual["projection"]["sha256"],
        }
        record = json.loads((root / ".cwo-install-manifest.json").read_bytes())
        assert record["source_dir"] == str(source) and record["version"] == 2 and record["status"] == "current"
        assert record["projection"] == expected["projection"]
        assert all(record[key] == expected["content_sha256"] for key in ("source_content_sha256", "installed_content_sha256"))
        assert all(record[key] == expected["file_count"] for key in ("source_file_count", "installed_file_count"))
        if mode == "normal":
            assert actual == expected
        else:
            difference = checker.compare_manifests(expected, actual)
            field = "changed_files" if mode in {"inventory", "changed-schema"} else "missing_files"
            assert difference[field] == [payload["dependency"]]
            assert all(not difference[key] for key in (
                "extra_files", "missing_entries", "mismatched_entries",
                "missing_files" if field == "changed_files" else "changed_files"))
        phase = "imports"
        if mode == "inventory":
            outcomes.append({"name": "inventory-refusal", "status": "refused", "exit_code": None, "result_sha256": digest(difference)})
        elif mode == "missing-module":
            try:
                importlib.import_module("prepare_in_thread_plan")
            except ModuleNotFoundError as error:
                assert error.name == "cwo_core.requirement_baseline"
                outcomes.append({"name": "import-refusal", "status": "refused", "exit_code": None,
                                 "result_sha256": digest({"type": type(error).__name__, "module": error.name})})
            else:
                raise AssertionError("EXAMPLE missing installed reliability dependency was accepted.")
        else:
            preview = importlib.import_module("prepare_in_thread_plan")
            rb = importlib.import_module("cwo_core.requirement_baseline")
            routing = importlib.import_module("cwo_core.routing")
            importlib.import_module("cwo_core.workspace_capture")
            importlib.import_module("cwo_core.beads")
            schemas = importlib.import_module("cwo_core.policy_schema")
            assert sorted(schemas.POLICY_VALIDATION_BOUNDARIES) == payload["policy_names"]
            assert schemas.POLICY_SCHEMAS == payload["schema_names"]
            phase = "calls"
            if mode == "normal":
                for case in payload["cases"]:
                    exercise(case)
                exercise_raw()
            else:
                exercise({**payload["cases"][0], "status": "refused"})
        phase = "origins"
        origin_rows = origins()
    except BaseException as error:
        failure = {"phase": phase, "type": type(error).__name__}
    measured, measured_reads, measured_cache = dict(effects), sorted(reads), sorted(cache_attempts)
    phase = "evidence"
    read_records = [identity(path) for path in measured_reads]
    record_identity = identity(root / ".cwo-install-manifest.json")
    security_identity = identity(root / "SECURITY.md")
    phase = "calls"
    try:
        control_counts = controls(full)
    except BaseException as error:
        if failure is None:
            failure = {"phase": "positive-controls", "type": type(error).__name__}
    sys.setprofile(None)
print(json.dumps({
    "ok": failure is None and not measured, "failure": failure, "mode": mode,
    "inputs": [identity(input_path)], "manifests": image,
    "install_record": record_identity, "security": security_identity,
    "origins": origin_rows, "outcomes": outcomes, "bindings": bindings,
    "reads": read_records, "cache_refusals": measured_cache,
    "measured_effects": measured, "positive_control_counts": control_counts,
    "attempted_effects": dict(effects), "watched_calls_total": dict(calls),
    "routing_inputs_total": dict(Counter(route_inputs)),
    "interpreter": {"path": str(Path(sys.executable).resolve()), "version": list(sys.version_info[:3])},
}, sort_keys=True))
raise SystemExit(0 if failure is None and not measured else 1)
'''


def request_fixture(amended=True):
    request = producer.example_request(amended=amended)
    if amended:
        criterion = producer.example_criterion("EXAMPLE-held-observation", "validator")
        criterion["requirement"] = "EXAMPLE a future held observation remains required."
        request["amendments"][0]["baseline"]["criteria"].append(criterion)
        request["amendments"][0]["added_criterion_ids"].append(criterion["id"])
    chain = producer.rb.resolve_chain(request["baseline"], request["amendments"])
    request["candidate"] = producer.example_candidate(chain)
    assert not producer.ci.candidate_errors(request["candidate"])
    assert not producer.ci.baseline_binding_errors(request["candidate"], chain)
    request["task"]["requested_roles"] = ["documentation"]
    return request


def cases(profile):
    base, result = request_fixture(), []

    def add(name, status="proposed-in-thread", changes=(), request=None, **checks):
        value = copy.deepcopy(base if request is None else request)
        for path, replacement in changes:
            target = value
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = replacement
        result.append({"name": name, "status": status, "request": value, **checks})

    add("documentation")
    add("manual", changes=[(("task", "requested_roles"), [])])
    aliases = ["documentation", profile["discipline"], profile["job_description_label"], *profile.get("aliases", [])]
    for index, role in enumerate(dict.fromkeys(role for alias in aliases for role in (alias, alias.upper()))):
        add(f"alias-{index}", changes=[(("task", "requested_roles"), [role])])
    for index, (roles, unknown) in enumerate((
        (["EXAMPLE_UNKNOWN"], [0]), (["documentation", "EXAMPLE_UNKNOWN"], [1]),
        (["EXAMPLE_UNKNOWN", "DOCUMENTATION"], [0]), (["EXAMPLE_UNKNOWN", "EXAMPLE_OTHER"], [0, 1]),
        (["documentation-EXAMPLE"], [0]), ([" documentation"], [0]), (["documentation "], [0]),
    )):
        add(f"unknown-{index}", "consequential-plan-needed", [(("task", "requested_roles"), roles)], unknown=unknown)
    for field in ("dependencies", "required_reviews", "holds", "delegation_requested"):
        obligation = {"id": "EXAMPLE-open", "reason": "EXAMPLE an independent obligation remains open."}
        if field == "dependencies":
            obligation["kind"] = "external"
        value = True if field == "delegation_requested" else [obligation]
        add(field, "consequential-plan-needed", [(("task", field), value)])
    for index, (text, gate) in enumerate((
        ("EXAMPLE Fix a docs typo and request ChatGPT Pro Extended Reasoning master plan review.", "blocking_review_required"),
        ("EXAMPLE Revise public docs wording.", "editor_gate_required"),
    )):
        add(f"gate-{index}", "consequential-plan-needed",
            [(("task", "text"), text), (("task", "text_segments"), [text])], gate=gate)
    for name, segments in (
        ("consequential", ["EXAMPLE Fix one-file docs typo for OIDC sign in and production rollout."]),
        ("appended", ["EXAMPLE Fix one typo in docs notes. Inspect sign ", "in", "g"]),
    ):
        add(name, "consequential-plan-needed",
            [(("task", "text"), "\n".join(segments)), (("task", "text_segments"), segments)], features=True)
    text = base["task"]["text"] + " EXAMPLE clearer copy."
    add("binding-context", changes=[(("task", "text"), text), (("task", "text_segments"), [text])], binding_change=True)
    add("binding-candidate", changes=[(("candidate", "tree"), digest(b"EXAMPLE different tree")[:40])], binding_change=True)
    add("binding-baseline", request=request_fixture(False), binding_change=True)
    add("binding-content", changes=[(("candidate", "worktree_manifest"), [{
        "path": "references/EXAMPLE-notes.md", "change": "modified", "type": "file",
        "mode": "100644", "size": 7, "sha256": digest(b"EXAMPLE"),
    }])], binding_change=True)
    for index, value in enumerate((True, "1", 1.0, 2)):
        add(f"version-{index}", "refused", [(("version",), value)])
    for field in ("baseline", "candidate"):
        add(field + "-version", "refused", [((field, "version"), True)])
    for name, path, value in (
        ("missing-criteria", ("baseline", "criteria"), []),
        ("replaced-criterion", ("amendments", 0, "baseline", "criteria", 0, "requirement"), "EXAMPLE replaced obligation."),
        ("missing-addition", ("amendments", 0, "added_criterion_ids"), []),
        ("candidate-binding", ("candidate", "baseline", "digest"), "sha256:" + digest(b"EXAMPLE different baseline")),
        ("candidate-identity", ("candidate", "commit"), "EXAMPLE_INVALID"),
        ("boolean-context", ("task", "delegation_requested"), 1),
        ("lost-segment", ("task", "text_segments"), ["EXAMPLE omitted original context."]),
    ):
        add(name, "refused", [(path, value)])
    for key, value in (("minimal", True), ("routing", {"risk_level": "low"}), ("reviews", [{"status": "approved"}])):
        changed = copy.deepcopy(base)
        changed[key] = value
        changed["task"]["holds"] = [{"id": "EXAMPLE-held", "reason": "EXAMPLE this obligation remains held."}]
        add("unsupported-" + key, "refused", request=changed)
    raw = canonical(base)
    raw_cases = [("valid", raw, "proposed-in-thread"), ("duplicate", b'{"version":1,' + raw[1:], "refused"),
                 ("syntax", b"{", "refused"), ("utf8", b"\xff", "refused"),
                 ("float", b'{"version":1.0}', "refused"), ("nonfinite", b'{"version":NaN}', "refused")]
    return result, [{"name": name, "octets": list(value), "status": status} for name, value, status in raw_cases]


class InstalledInThreadPlanConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        seed = cls("test_installed_in_thread_plan_lifecycle_without_source")
        cls.addClassCleanup(seed.cleanup_install)
        seed.prepare_install()
        seed.source = seed.install.copy_source()
        seed.expected = fixture.checker.build_manifest(seed.source)
        seed.real_install("fresh-install")
        cls.seed_source, cls.seed_target = seed.source, seed.install.target
        cls.seed_hashes = tuple(digest(fixture.snapshot(path)) for path in (cls.seed_source, cls.seed_target))
        cls.addClassCleanup(cls.verify_seed)
        print("CWO_INSTALLED_IN_THREAD_SEED " + json.dumps({"schema": "cwo-installed-in-thread-seed-v1",
                "authority": "collector observations only", **dict.fromkeys(FALSE_FIELDS, False),
                "source": str(seed.source), "target": str(seed.install.target),
                "manifest_sha256": digest(seed.expected), "snapshot_sha256": cls.seed_hashes,
                "source_snapshots": seed.snapshots, "outcomes": seed.install_outcomes},
                sort_keys=True, separators=(",", ":")), flush=True)

    @classmethod
    def verify_seed(cls):
        actual = tuple(digest(fixture.snapshot(path)) for path in (cls.seed_source, cls.seed_target))
        if actual != cls.seed_hashes:
            raise AssertionError("EXAMPLE installed reliability seed changed.")

    def prepare_install(self):
        self.install = fixture.InstallerProjectionTests("test_fresh_install_is_the_projection_and_its_resources_are_usable")
        self.addCleanup(self.cleanup_install)
        self.install.setUp()
        self.assertFalse(self.install.tmp.resolve().is_relative_to(fixture.ROOT.resolve()))
        self.env = {**os.environ, "HOME": str(self.install.tmp / "home"), "PYTHONDONTWRITEBYTECODE": "1",
                    "SKILL_VALIDATOR": str(self.install.tmp / "EXAMPLE_no_validator.py"),
                    "PATH": str(self.install.shims) + os.pathsep + os.environ.get("PATH", os.defpath)}
        for key in ("CODEX_HOME", "CODEX_SKILLS_DIR", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "BASH_ENV", "ENV"):
            self.env.pop(key, None)
        self.snapshots, self.install_outcomes, self.coordinates = [], [], {}

    def setUp(self):
        self.prepare_install()
        self.source = self.copy_seed_tree(self.seed_source, self.install.tmp / "source")
        self.expected = fixture.checker.build_manifest(self.source)
        self.checkout_manifest = fixture.checker.build_manifest(fixture.ROOT)
        self.source_ids = [identity(path) for path in (
            Path(__file__), Path(producer.__file__), Path(fixture.__file__),
            fixture.ROOT / "tests/test_installed_numeric_rollback.py",
            fixture.ROOT / "scripts/prepare_in_thread_plan.py",
            fixture.ROOT / "references/installed-plan-consumer-contract.md",
        )]
        self.copy_seed_install()
        prepare_replacement(self)

    def copy_seed_tree(self, seed, destination):
        before = fixture.snapshot(seed)
        shutil.copytree(seed, destination)
        self.assertEqual(fixture.snapshot(destination), before)
        self.assertEqual(destination.stat().st_mode, seed.stat().st_mode)
        for relative, (mode, _) in before.items():
            if fixture.stat.S_ISREG(mode):
                self.assertFalse(os.path.samefile(seed / relative, destination / relative))
        return destination

    def copy_seed_install(self):
        self.copy_seed_tree(self.seed_target, self.install.target)
        path = self.install.target / RECORD
        before = path.read_bytes()
        record = json.loads(before)
        self.assertEqual(record["source_dir"], str(self.seed_source))
        # Only this inert coordinate is rebound; the seed's real installer receipt
        # is retained separately, never reported as an install of this copy.
        record["source_dir"] = str(self.source)
        path.write_bytes(canonical(record) + b"\n")
        self.assert_image(self.install.target, self.expected)
        self.install_outcomes.append({
            "name": "private-seed-copy", "status": "copied-and-verified", "exit_code": None,
            "seed_record_sha256": digest(before), "private_record": identity(path),
            "result_sha256": digest({"source": str(self.source), "target": str(self.install.target),
                                     "manifest": self.expected}),
        })

    def cleanup_install(self):
        temporary = getattr(self.install, "_tmp", None)
        try:
            self.install.doCleanups()
        finally:
            if temporary is not None:
                temporary.cleanup()

    def run_install(self, phase, **extra):
        before = fixture.snapshot(self.source)
        result = bounded_run(phase, ["bash", str(self.source / "scripts/install.sh"),
                             "--skills-dir", str(self.install.skills), "--yes"],
                             cwd=self.install.tmp / "home", env={**self.env, **extra}, text=True)
        self.assertTrue(fixture.snapshot(self.source) == before, "EXAMPLE installer changed its reliability source.")
        self.snapshots.append({"phase": phase, "before_sha256": digest(before), "after_sha256": digest(fixture.snapshot(self.source))})
        self.install_outcomes.append({"name": phase, "status": "returned", "exit_code": result.returncode,
                                      "result_sha256": digest({"stdout": output_summary(result.stdout), "stderr": output_summary(result.stderr)})})
        return result

    def assert_image(self, root, expected):
        actual = fixture.checker.build_manifest(root)
        self.assertTrue(actual == expected, "EXAMPLE complete installed reliability inventory differs.")
        files = {path for path, (mode, _) in fixture.snapshot(root).items() if fixture.stat.S_ISREG(mode) and path != RECORD}
        self.assertEqual(files, {item["path"] for item in expected["files"]})
        record = json.loads((root / RECORD).read_bytes())
        self.assertEqual((record["version"], record["status"], record["source_dir"]), (2, "current", str(self.source)))
        self.assertEqual(record["projection"], expected["projection"])
        for field in ("source_content_sha256", "installed_content_sha256"):
            self.assertEqual(record[field], expected["content_sha256"])
        for field in ("source_file_count", "installed_file_count"):
            self.assertEqual(record[field], expected["file_count"])
        self.assertFalse((root / "tests").exists())
        self.assertTrue(os.access(root / "scripts/install.sh", os.X_OK))

    def real_install(self, phase):
        result = self.run_install(phase)
        self.assertEqual(result.returncode, 0, json.dumps({"phase": phase, "stderr": output_summary(result.stderr)}))
        self.assert_image(self.install.target, self.expected)

    def replacement(self):
        before = fixture.snapshot(self.source)
        security = self.source / "SECURITY.md"
        security.write_bytes(security.read_bytes() + b"\nEXAMPLE disposable reliability replacement marker.\n")
        after = fixture.snapshot(self.source)
        self.assertEqual(set(before), set(after))
        self.assertEqual({path for path in before if before[path] != after[path]}, {"SECURITY.md"})
        replacement = fixture.checker.build_manifest(self.source)
        self.assertEqual(fixture.checker.compare_manifests(self.expected, replacement)["changed_files"], ["SECURITY.md"])
        return replacement

    def rollback(self, mode):
        previous = fixture.snapshot(self.install.target)
        replacement = self.replacement()
        witness, event = self.install.tmp / ("EXAMPLE_witness_" + mode), self.install.tmp / ("EXAMPLE_coordinates_" + mode)
        shim = self.install.shims / "mv"
        self.addCleanup(shim.unlink, missing_ok=True)
        self.install.write_shim("mv", MV_SHIM)
        try:
            result = self.run_install(mode, CWO_TEST_INTERRUPT=mode, CWO_TEST_TARGET=str(self.install.target),
                                      CWO_TEST_SKILLS=str(self.install.skills), CWO_TEST_BACKUPS=str(self.install.backups),
                                      CWO_TEST_SKILL=fixture.SKILL, CWO_TEST_WITNESS=str(witness), CWO_TEST_EVENT=str(event))
        finally:
            shim.unlink(missing_ok=True)
        self.assertEqual(result.returncode, 143 if mode == "term" else 1)
        if mode == "activation":
            self.assertIn("could not activate staged install", result.stderr)
        self.assertIn(f"Restored the previous install at {self.install.target}", result.stderr.splitlines())
        self.assertTrue(fixture.snapshot(self.install.target) == previous, "EXAMPLE rollback changed restored reliability bytes or modes.")
        self.assertEqual(self.install.leftovers(), [])
        stage, backup = (Path(line) for line in event.read_text(encoding="utf-8").splitlines())
        self.assertEqual((stage.parent, backup.parent), (self.install.skills, self.install.backups))
        self.assertTrue(stage.name.startswith(f".{fixture.SKILL}.stage.") and backup.name.startswith(f"{fixture.SKILL}.prev."))
        self.assert_image(witness, replacement)
        self.assert_image(self.install.target, self.expected)
        self.coordinates = {"stage": str(stage), "backup": str(backup), "witness": str(witness),
                            "event": identity(event), "witness_manifest_sha256": digest(fixture.checker.build_manifest(witness)),
                            "restored_snapshot_sha256": digest(previous)}
        shutil.rmtree(witness)

    def prepare_inputs(self, dependencies):
        policies = producer.policy_schema
        profile = json.loads((self.source / "policy/expert-registry.yaml").read_bytes())["experts"]["documentation"]
        supplied_cases, raw = cases(profile)
        paths = {item["path"] for item in self.expected["files"]}
        required = {"SECURITY.md", "scripts/prepare_in_thread_plan.py", "scripts/check_installed_skill.py",
                    "scripts/cwo_core/candidate_identity.py", "scripts/cwo_core/requirement_baseline.py"}
        required |= {"policy/" + name for name in policies.POLICY_VALIDATION_BOUNDARIES}
        required |= {"schemas/" + name for name in policies.POLICY_SCHEMAS.values()}
        self.assertTrue(required <= paths, "EXAMPLE installed reliability dependencies are missing.")
        base = {"manifest": self.expected, "cases": supplied_cases, "raw": raw,
                "policy_names": sorted(policies.POLICY_VALIDATION_BOUNDARIES), "schema_names": policies.POLICY_SCHEMAS}
        images = [("normal", self.install.target, None)]
        if dependencies:
            for mode, relative in (
                ("missing-module", "scripts/cwo_core/requirement_baseline.py"),
                ("missing-policy", "policy/routing-policy.yaml"),
                ("changed-schema", "schemas/routing-policy.schema.json"),
                ("inventory", "scripts/prepare_in_thread_plan.py"),
            ):
                root = self.install.tmp / ("EXAMPLE_" + mode) / fixture.SKILL
                shutil.copytree(self.install.target, root)
                path = root / relative
                if mode.startswith("missing"):
                    path.unlink()
                else:
                    path.write_bytes(b"{}\n" if mode == "changed-schema" else path.read_bytes() + b"\n# EXAMPLE reliability drift.\n")
                images.append((mode, root, relative))
        prepared = []
        for mode, root, dependency in images:
            path = self.install.tmp / ("EXAMPLE_" + mode + "_input.json")
            path.write_bytes(canonical({**base, "mode": mode, "dependency": dependency}))
            prepared.append((mode, root, path))
        return prepared

    def validate_report(self, report, mode, root, path):
        self.assertIs(report["ok"], True, json.dumps(report["failure"], sort_keys=True))
        self.assertEqual(report["mode"], mode)
        self.assertEqual(report["inputs"], [identity(path)])
        actual = fixture.checker.build_manifest(root, strict=False)
        self.assertEqual(report["manifests"], {
            "expected_sha256": digest(self.expected), "installed_sha256": digest(actual),
            "content_sha256": actual["content_sha256"], "file_count": actual["file_count"],
            "projection_sha256": actual["projection"]["sha256"],
        })
        self.assertEqual(report["install_record"], identity(root / RECORD))
        self.assertEqual(report["security"], identity(root / "SECURITY.md"))
        self.assertEqual(report["interpreter"], {"path": str(Path(sys.executable).resolve()), "version": list(sys.version_info[:3])})
        self.assertEqual(report["measured_effects"], {})
        controls = dict.fromkeys(BASE_EFFECTS + (NAMED_EFFECTS if mode not in {"inventory", "missing-module"} else ()), 1)
        controls["read"] = 5
        self.assertEqual(report["positive_control_counts"], controls)
        self.assertEqual(report["attempted_effects"], controls)
        for item in report["reads"]:
            self.assertEqual(item, identity(item["path"]))
            resolved = Path(item["path"])
            self.assertTrue(resolved.is_relative_to(root) or resolved == path or resolved.is_relative_to(Path(os.__file__).resolve().parent))
        for cached in report["cache_refusals"]:
            self.assertFalse(Path(cached).exists())
        modules = set()
        for item in report["origins"]:
            origin = Path(item["path"])
            self.assertTrue(origin.is_relative_to(root / "scripts"))
            self.assertEqual(item["sha256"], identity(origin)["sha256"])
            self.assertEqual(item["spec"], str(origin))
            self.assertEqual(item["package_paths"], [str(origin.parent)] if origin.name == "__init__.py" else [])
            self.assertNotIn(item["module"], modules)
            modules.add(item["module"])
        self.assertTrue({"check_installed_skill", "cwo_core"} <= modules)
        if mode not in {"inventory", "missing-module"}:
            self.assertTrue({"prepare_in_thread_plan", "cwo_core.candidate_identity", "cwo_core.requirement_baseline",
                             "cwo_core.routing", "cwo_core.policy", "cwo_core.policy_schema"} <= modules)
        payload = json.loads(path.read_bytes())
        self.validate_outcomes(report, payload, mode)
        self.validate_measurements(report, payload, mode)

    def validate_outcomes(self, report, payload, mode):
        outcomes = report["outcomes"]
        self.assertEqual(len({item["name"] for item in outcomes}), len(outcomes))
        if mode in {"inventory", "missing-module"}:
            self.assertEqual(len(outcomes), 1)
            self.assertEqual(outcomes[0]["status"], "refused")
            return
        expected = {}
        for case in payload["cases"] if mode == "normal" else [{**payload["cases"][0], "status": "refused"}]:
            for suffix in ("library", "json", "main"):
                expected[case["name"] + ":" + suffix] = (case["status"], (0 if case["status"] == "proposed-in-thread" else 1) if suffix == "main" else None)
        if mode == "normal":
            for case in payload["raw"]:
                for suffix in ("json", "main"):
                    expected["raw-" + case["name"] + ":" + suffix] = (case["status"], (0 if case["status"] == "proposed-in-thread" else 1) if suffix == "main" else None)
            expected.update({"argument---help": ("refused", 1), "argument---minimal": ("refused", 1)})
        self.assertEqual({item["name"]: (item["status"], item["exit_code"]) for item in outcomes}, expected)
        hashes = {item["name"]: item["result_sha256"] for item in outcomes}
        diagnostics = {item["name"]: item["errors_sha256"] for item in outcomes}
        for name in expected:
            self.assertRegex(hashes[name], r"^[0-9a-f]{64}$")
            self.assertRegex(diagnostics[name], r"^[0-9a-f]{64}$")
            if name.endswith(":json"):
                main = name.removesuffix(":json") + ":main"
                self.assertEqual(hashes[name], hashes[main])
                self.assertEqual(diagnostics[name], diagnostics[main])
            if name.endswith(":library"):
                decoded = name.replace(":library", ":json")
                if mode == "normal" and name == "version-2:library":
                    self.assertNotEqual(hashes[name], hashes[decoded])
                else:
                    self.assertEqual(hashes[name], hashes[decoded])
                    self.assertEqual(diagnostics[name], diagnostics[decoded])
        if mode == "normal":
            value = next(case["request"]["version"] for case in payload["cases"] if case["name"] == "version-2")
            self.assertIs(type(value), float)
            self.assertEqual(value, 1.0)
            self.assertEqual(diagnostics["version-2:library"],
                             digest(["Input contains an unsupported JSON type."]))
            self.assertEqual(diagnostics["version-2:json"],
                             digest(["JSON floats and nonfinite numbers are unsupported."]))
            self.assertEqual(hashes["documentation:library"], hashes["raw-valid:json"])
            self.assertNotEqual(hashes["raw-valid:json"], hashes["raw-duplicate:json"])

    def validate_observation(self, observation):
        self.assertIs(type(observation), dict)
        self.assertEqual(set(observation), {"validator_calls", "routing_inputs"})
        self.assertIs(type(observation["validator_calls"]), dict)
        self.assertIs(type(observation["routing_inputs"]), dict)
        self.assertEqual(set(observation["validator_calls"]), set(WATCHED_CALLS))
        self.assertTrue(all(type(count) is int and count >= 0 for count in observation["validator_calls"].values()))
        for hashed, count in observation["routing_inputs"].items():
            self.assertRegex(hashed, r"^[0-9a-f]{64}$")
            self.assertIs(type(count), int)
            self.assertGreater(count, 0)

    def validate_case_observations(self, outcome, task):
        helper, oracles = outcome["helper_observation"], outcome["oracle_observations"]
        self.validate_observation(helper)
        self.assertIs(type(oracles), dict)
        required = outcome["status"] != "refused"
        names = {"baseline", "routing"} if required and outcome["name"].endswith(":library") else set()
        self.assertEqual(set(oracles), names)
        if not required:
            return
        self.assertIsNotNone(task)
        expected_inputs = {digest({
            **{key: task[key] for key in ("text", "text_segments", "file_paths", "requested_roles", "data_sensitivity")},
            "share_boundary": "no-outside-sharing", "external_ok": False, "local_ok": False, "prefer_local": False,
            "allow_disclosure_escalation": False, "current_authority": None,
            "operative_evaluated_at": "2000-01-01T00:00:00Z",
        }): 1}
        self.assertTrue(all(helper["validator_calls"][key] > 0 for key in WATCHED_CALLS))
        self.assertEqual(helper["routing_inputs"], expected_inputs)
        for observation in oracles.values():
            self.validate_observation(observation)
        if oracles:
            baseline, routing = oracles["baseline"], oracles["routing"]
            self.assertGreater(baseline["validator_calls"][WATCHED_CALLS[0]], 0)
            self.assertEqual(baseline["validator_calls"][WATCHED_CALLS[1]], 1)
            self.assertEqual({key: baseline["validator_calls"][key] for key in WATCHED_CALLS[2:]},
                             dict.fromkeys(WATCHED_CALLS[2:], 0))
            self.assertEqual(baseline["routing_inputs"], {})
            self.assertEqual(routing["validator_calls"], {**dict.fromkeys(WATCHED_CALLS, 0), WATCHED_CALLS[-1]: 1})
            self.assertEqual(routing["routing_inputs"], expected_inputs)

    def validate_measurements(self, report, payload, mode):
        if mode in {"inventory", "missing-module"}:
            self.assertFalse(report["watched_calls_total"] or report["routing_inputs_total"])
            self.assertTrue(all("helper_observation" not in item and "oracle_observations" not in item
                                for item in report["outcomes"]))
            return
        tasks = {case["name"]: case["request"]["task"] for case in payload["cases"]}
        tasks["raw-valid"] = payload["cases"][0]["request"]["task"]
        for outcome in report["outcomes"]:
            task = tasks.get(outcome["name"].rsplit(":", 1)[0])
            self.validate_case_observations(outcome, task)
        totals = observation_totals(report["outcomes"])
        for field, key in (("validator_calls", "watched_calls_total"), ("routing_inputs", "routing_inputs_total")):
            self.assertEqual(Counter(report[key]), Counter(totals["helper"][field]) + Counter(totals["oracle"][field]))

    def _lifecycle_metadata(self):
        return {"source_snapshots": self.snapshots, "coordinates": self.coordinates,
                "install_outcomes": self.install_outcomes}

    def consume(self, scenario, dependencies=False, rows=None):
        prepared = self.prepare_inputs(dependencies)
        self.assertEqual(self.source, self.install.tmp / "source")
        shutil.rmtree(self.source)
        before, reports = fixture.snapshot(self.install.tmp), []
        bootstrap = "import runpy,sys;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('check_installed_skill',run_name='__main__')"
        checked = bounded_run("installed-checker", [sys.executable, "-I", "-B", "-c", bootstrap,
                              str(self.install.target / "scripts"), "--source-dir", str(self.install.target),
                              "--installed-dir", str(self.install.target), "--check", "--json"],
                              cwd=self.install.tmp / "home", env=self.env, timeout=180)
        self.assertEqual(checked.returncode, 0, json.dumps(output_summary(checked.stderr)))
        self.assertEqual(json.loads(checked.stdout)["status"], "current")
        for mode, root, path in prepared:
            result = bounded_run("installed-consumer-" + mode,
                                 [sys.executable, "-I", "-B", "-c", PROBE, str(root), str(fixture.ROOT.resolve()),
                                  str(self.source), str(self.install.tmp), str(path), identity(path)["sha256"]],
                                 cwd=self.install.tmp / "home", env=self.env,
                                 timeout=360 if mode == "normal" else 180)
            self.assertEqual(result.returncode, 0, json.dumps({"stdout": output_summary(result.stdout), "stderr": output_summary(result.stderr)}))
            self.assertLessEqual(len(result.stdout), 8 * 1024 * 1024)
            report = json.loads(result.stdout)
            self.validate_report(report, mode, root, path)
            reports.append(report)
        self.assertTrue(fixture.snapshot(self.install.tmp) == before, "EXAMPLE installed reliability observation changed private files.")
        self.assertEqual(fixture.checker.build_manifest(fixture.ROOT), self.checkout_manifest)
        self.assertEqual([identity(item["path"]) for item in self.source_ids], self.source_ids)
        primary = reports[0]
        self.assertEqual(primary["manifests"]["expected_sha256"], primary["manifests"]["installed_sha256"])
        for row in rows or [{"row_id": scenario, "metadata": self._lifecycle_metadata()}]:
            metadata = row["metadata"]
            retained = {
                "schema": SCHEMA, "scenario": row["row_id"], "authority": "collector observations only",
                "shared_product_flow_sha256": digest(reports),
                **dict.fromkeys(FALSE_FIELDS, False), "inputs": [item for report in reports for item in report["inputs"]],
                "origins": [item for report in reports for item in report["origins"]],
                "outcomes": metadata["install_outcomes"] + [
                    {**item, "name": report["mode"] + ":" + item["name"]} for report in reports for item in report["outcomes"]],
                "manifests": primary["manifests"], "install_record": primary["install_record"], "security": primary["security"],
                "interpreter": {**primary["interpreter"], "sha256": identity(sys.executable)["sha256"]},
                "source_identities": self.source_ids, "source_snapshots": metadata["source_snapshots"],
                "coordinates": metadata["coordinates"],
                "observations": [normalized_observation(report) for report in reports],
                "scenario_outcome_sha256": digest({"scenario": row["row_id"], "snapshots": metadata["source_snapshots"],
                                                   "coordinates": metadata["coordinates"], "outcomes": metadata["install_outcomes"]}),
            }
            retain(retained, sys.stdout)

    def test_installed_in_thread_plan_lifecycle_without_source(self):
        self.assertEqual(self.install.leftovers(), [])

        def cleanup(case):
            self.assertTrue(case.doCleanups(), "EXAMPLE private seed-copy cleanup failed.")

        failed = unittest.TestCase()
        failed.addCleanup(self.fail, "EXAMPLE injected cleanup failure.")
        with self.assertRaisesRegex(AssertionError, "EXAMPLE private seed-copy cleanup failed"):
            cleanup(failed)

        other = type(self)(self._testMethodName)
        other.fixture_variant = "ordinary"
        before = fixture.snapshot(self.install.tmp)
        try:
            other.setUp()
            self.assertNotEqual(self.install.tmp, other.install.tmp)
            self.assertEqual(self.expected, other.expected)
            self.assertIsNot(self.snapshots, other.snapshots)
            self.assertIsNot(self.install_outcomes, other.install_outcomes)
            self.assertIsNot(self.coordinates, other.coordinates)
            for root in (other.source, other.install.target):
                marker = root / "SECURITY.md"
                marker.write_bytes(marker.read_bytes() + b"\nEXAMPLE private seed-copy mutation.\n")
                marker.chmod(0o600)
            other.coordinates["EXAMPLE"] = "private"
            other.snapshots.append({"EXAMPLE": "private"})
            other.install_outcomes.append({"EXAMPLE": "private"})
            self.assertEqual(fixture.snapshot(self.install.tmp), before)
            self.verify_seed()
        finally:
            cleanup(other)
        shared = RestoredInstalledRows(self, self._lifecycle_metadata)
        shared.exercise_rollbacks()
        shared.retain()
        with self.subTest(rows=("fresh", "activation-rollback", "term-rollback")):
            self.consume("fresh", dependencies=True, rows=shared.rows)
        with self.subTest(row="replacement"):
            self.replacement_case.replacement_row()

    def replacement_row(self):
        previous = fixture.snapshot(self.install.target)
        self.expected = self.replacement()
        self.real_install("replacement-install")
        backups = list(self.install.backups.glob(f"{fixture.SKILL}.prev.*"))
        self.assertEqual(len(backups), 1)
        self.assertTrue(fixture.snapshot(backups[0]) == previous, "EXAMPLE reliability replacement backup differs.")
        self.coordinates = {"backup": str(backups[0]), "backup_snapshot_sha256": digest(previous)}
        self.assertEqual(list(self.install.skills.glob(f".{fixture.SKILL}.stage.*")), [])
        self.consume("replacement")


class InstalledInThreadEvidenceControlTests(unittest.TestCase):

    def child_namespace(self):
        tree = ast.parse(PROBE)
        body = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef))]
        namespace = {
            "preview": producer.preview, "rb": producer.rb, "routing": producer.routing,
            "calls": Counter(), "effects": Counter(), "route_inputs": [], "outcomes": [], "bindings": {},
            "false_fields": FALSE_FIELDS,
        }
        exec(compile(ast.Module(body=body, type_ignores=[]), "<EXAMPLE reliability declarations>", "exec"), namespace)
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if node.targets[0].id in {"named", "watched"}:
                    namespace[node.targets[0].id] = ast.literal_eval(node.value)
        namespace["observed_names"] = {key[1] for key in namespace["named"]} | {key[1] for key in namespace["watched"]}
        return namespace

    def test_real_api_and_oracle_measurements_remain_separate(self):
        namespace = self.child_namespace()
        case = {"name": "documentation", "status": "proposed-in-thread", "request": request_fixture()}
        previous = sys.getprofile()
        try:
            sys.setprofile(namespace["profile"])
            namespace["exercise"](case)
        finally:
            sys.setprofile(previous)
        self.assertEqual(len(namespace["outcomes"]), 3)
        report = {
            "outcomes": namespace["outcomes"], "watched_calls_total": dict(namespace["calls"]),
            "routing_inputs_total": dict(Counter(namespace["route_inputs"])),
        }
        validator = InstalledInThreadPlanConsumerTests("test_installed_in_thread_plan_lifecycle_without_source")
        validator.validate_measurements(report, {"cases": [case]}, "normal")
        for index in range(3):
            changed = copy.deepcopy(report)
            helper = changed["outcomes"][index]["helper_observation"]["validator_calls"]
            for key in WATCHED_CALLS[:2]:
                changed["watched_calls_total"][key] -= helper[key]
                helper[key] = 0
            with self.subTest(api=index), self.assertRaises(AssertionError):
                validator.validate_measurements(changed, {"cases": [case]}, "normal")
        changed = copy.deepcopy(report)
        oracle = changed["outcomes"][0]["oracle_observations"]["baseline"]["validator_calls"]
        for key in WATCHED_CALLS[:2]:
            changed["watched_calls_total"][key] -= oracle[key]
            oracle[key] = 0
        with self.assertRaises(AssertionError):
            validator.validate_measurements(changed, {"cases": [case]}, "normal")

    def test_each_api_requires_its_own_observations_before_oracles(self):
        case = {"name": "documentation", "status": "proposed-in-thread", "request": request_fixture()}
        boundaries = {("cwo_core.requirement_baseline", name) for name in ("baseline_errors", "resolve_chain")}
        for api in ("prepare_proposal", "prepare_json", "main"):
            namespace, omitted = self.child_namespace(), Counter()

            def observe(frame, event, arg):
                key = (frame.f_globals.get("__name__"), frame.f_code.co_name)
                if event == "call" and key in boundaries:
                    parent, owner = frame.f_back, None
                    while parent is not None:
                        if parent.f_globals.get("__name__") == "prepare_in_thread_plan":
                            if parent.f_code.co_name in {"prepare_proposal", "prepare_json", "main"}:
                                owner = parent.f_code.co_name
                        parent = parent.f_back
                    if owner == api:
                        omitted[".".join(key)] += 1
                        return
                return namespace["profile"](frame, event, arg)

            previous = sys.getprofile()
            try:
                sys.setprofile(observe)
                with self.subTest(api=api), self.assertRaisesRegex(AssertionError, "reliability API observations are incomplete"):
                    namespace["exercise"](case)
            finally:
                sys.setprofile(previous)
            self.assertEqual(set(omitted), set(WATCHED_CALLS[:2]))
            self.assertTrue(all(count > 0 for count in omitted.values()))

    def test_held_requirements_need_exact_native_list_elements(self):
        namespace = self.child_namespace()
        result = producer.preview.prepare_proposal(request_fixture())
        required = ["Full production closure qualification remains open.", "In-thread plan activation remains open."]
        self.assertEqual(result["status"], "proposed-in-thread")
        self.assertEqual(result["open_requirements"], required)
        namespace["held"](result)
        for value in (" ".join(required), dict.fromkeys(required, True), [" ".join(required)],
                      required[:1], required[1:], [*required, False]):
            changed = copy.deepcopy(result)
            changed["open_requirements"] = value
            with self.subTest(kind=type(value).__name__), self.assertRaises(AssertionError):
                namespace["held"](changed)

    def test_named_controls_reach_real_entries_before_effects(self):
        names = {"named", "watched", "observed_names", "EffectRefused", "block", "profile", "named_controls"}
        body = []
        for node in ast.parse(PROBE).body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names:
                body.append(node)
            elif isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id in names for target in node.targets
            ):
                body.append(node)
        namespace = {"effects": Counter({"read": 2}), "calls": Counter(), "route_inputs": []}
        exec(compile(ast.Module(body=body, type_ignores=[]), "<EXAMPLE reliability controls>", "exec"), namespace)
        functions = {
            "capture-candidate": producer.ci.capture_candidate,
            "verify-candidate": producer.ci.verify_candidate,
            "capture-workspace": producer.workspace_capture.capture,
            "beads-run": producer.beads.run_bd,
            "beads-structured": producer.beads.run_bd_structured,
            "beads-create": producer.beads.create_bead,
            "beads-link": producer.beads.add_dependency,
        }
        code_names = {function.__code__: name for name, function in functions.items()}
        probes = namespace["named_controls"](producer.ci, producer.workspace_capture, producer.beads)
        self.assertEqual([name for name, _ in probes], list(NAMED_EFFECTS))
        reached, counts = [], Counter()

        def observe(frame, event, arg):
            if event == "call" and frame.f_code in code_names:
                reached.append(code_names[frame.f_code])
                namespace["profile"](frame, event, arg)
                raise AssertionError("EXAMPLE reliability named observation is missing.")

        for name, call in probes:
            with self.subTest(control=name):
                before, previous = namespace["effects"].copy(), sys.getprofile()
                reached.clear()
                try:
                    sys.setprofile(observe)
                    with self.assertRaises(namespace["EffectRefused"]) as caught:
                        call()
                finally:
                    sys.setprofile(previous)
                self.assertEqual(reached, [name])
                self.assertEqual(caught.exception.args, (name,))
                before[name] += 1
                self.assertEqual(namespace["effects"], before)
                counts[name] += 1
        self.assertEqual(dict(counts), dict.fromkeys(NAMED_EFFECTS, 1))
        self.assertEqual(namespace["effects"]["read"], 2)

    def test_evidence_is_flushed_and_survives_cleanup(self):
        events = []

        class Recording(io.StringIO):
            def flush(self):
                events.append("flushed")
                super().flush()

        stream = Recording()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "EXAMPLE_input"
            path.write_bytes(b"EXAMPLE reliability input.")
            record = {"schema": SCHEMA, "scenario": "fresh", "inputs": [identity(path)]}
            retain(record, stream)
            self.assertEqual(events, ["flushed"])
        self.assertFalse(path.exists())
        self.assertEqual(json.loads(stream.getvalue().removeprefix(PREFIX)), record)

    def test_timeouts_are_bounded_phase_failures(self):
        for phase in (
            "fresh-install", "replacement-install", "activation", "term", "installed-checker",
            "installed-consumer-normal", "installed-consumer-missing-module", "installed-consumer-missing-policy",
            "installed-consumer-changed-schema", "installed-consumer-inventory",
        ):
            error = subprocess.TimeoutExpired(["EXAMPLE_PRIVATE_COMMAND"], 1, output=b"EXAMPLE_PRIVATE_OUTPUT", stderr=b"EXAMPLE_PRIVATE_ERROR")
            with self.subTest(phase=phase), patch.object(subprocess, "run", side_effect=error):
                with self.assertRaises(AssertionError) as caught:
                    bounded_run(phase, ["EXAMPLE_PRIVATE_COMMAND"], timeout=1)
                rendered = "".join(traceback.format_exception(caught.exception))
                diagnostic = json.loads(str(caught.exception))
                self.assertEqual((diagnostic["status"], diagnostic["phase"]), ("timeout", phase))
                self.assertEqual(diagnostic["stdout"], output_summary(error.stdout))
                self.assertEqual(diagnostic["stderr"], output_summary(error.stderr))
                self.assertTrue(caught.exception.__suppress_context__)
                for forbidden in ("EXAMPLE_PRIVATE_COMMAND", "EXAMPLE_PRIVATE_OUTPUT", "EXAMPLE_PRIVATE_ERROR", PREFIX):
                    self.assertNotIn(forbidden, rendered)
        unrelated = RuntimeError("EXAMPLE unrelated reliability failure.")
        with patch.object(subprocess, "run", side_effect=unrelated), self.assertRaises(RuntimeError) as caught:
            bounded_run("EXAMPLE-unrelated", [])
        self.assertIs(caught.exception, unrelated)



if __name__ == "__main__":
    unittest.main()
