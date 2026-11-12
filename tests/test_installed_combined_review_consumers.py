"""Disposable installed combined-review reliability preparation; qualification is deferred."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import traceback
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tests.installed_consumer_fixtures import RestoredInstalledRows, prepare_replacement
from tests import test_combined_review_binding_preparation as examples
from tests import test_install_projection as image
from tests import test_installed_final_review_consumers as observation
from tests import test_installed_numeric_rollback as rollback_fixture

binding = examples.binding
ci, rb, cc = examples.ci, examples.rb, examples.cc
wc = observation.capture_fixture
RECORD = ".cwo-install-manifest.json"
SCHEMA = "cwo-installed-combined-review-consumer-evidence-v1"
MARKER = "CWO_INSTALLED_COMBINED_REVIEW_EVIDENCE "
DEFER_QUALIFICATION = True
PHASES = ("install", "installed-check", "restored-check", "installed-consumer", "installed-image")
GUARD_NAMES = frozenset((
    "read", "write", "mutation", "process-run", "process-Popen", "process-audit", "network",
    "beads-run", "beads-structured", "beads-create", "beads-link", "closure", "validator", "stage",
))
CONTROL_COUNTS = {
    "read": 5, "write": 4, "mutation": 1, "process-run": 2, "process-Popen": 4, "process-audit": 4,
    "network": 1, "beads-run": 1, "beads-structured": 1, "beads-create": 1, "beads-link": 1,
    "closure": 1, "validator": 1, "stage": 1,
}


import ast
import re

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def require(condition, message):
    if not condition:
        raise AssertionError("EXAMPLE reliability check failed: " + message)


def validate_guard_counts(report):
    require(type(report) is dict, "the reliability report must be an object")
    for field, wanted in (("effects", 0), ("control_effects", CONTROL_COUNTS)):
        values = report.get(field)
        require(type(values) is dict and set(values) == GUARD_NAMES,
                "the reliability guard inventory differs")
        require(all(type(values[name]) is int
                    and values[name] == (wanted[name] if type(wanted) is dict else wanted)
                    for name in GUARD_NAMES), "the reliability guard counts differ")


def stream_identity(value):
    data = value.encode("utf-8") if isinstance(value, str) else value or b""
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def parent_call(phase, call, *args, **kwargs):
    require(phase in PHASES, "the parent phase is undeclared")
    try:
        return call(*args, **kwargs)
    except subprocess.TimeoutExpired as error:
        command = error.cmd
        words = list(command) if isinstance(command, (list, tuple)) else [command]
        normalized = [os.fspath(word) if isinstance(word, (str, os.PathLike))
                      else type(word).__name__ for word in words]
        metadata = {"phase": phase, "type": "TimeoutExpired", "command_count": len(words),
                    "command_sha256": digest(normalized),
                    "stdout": stream_identity(error.output), "stderr": stream_identity(error.stderr)}
        raise AssertionError(json.dumps(metadata, sort_keys=True)) from None


def process_identity(phase, result):
    return json.dumps({"phase": phase, "returncode": result.returncode,
                       "stdout": stream_identity(result.stdout),
                       "stderr": stream_identity(result.stderr)}, sort_keys=True)


def cli_summary(result):
    return {"record_type": "cwo-combined-review-cli-diagnostic", "version": 1,
            **dict.fromkeys(binding.FALSE_FIELDS, False),
            **{key: result[key] for key in ("binding_consistent", "combined_observations_complete",
                                           "review_verdict", "remaining_open", "errors")},
            "snapshot_available": result["snapshot"] is not None,
            "report_sha256": "sha256:" + digest(result)}


def parent_cli(data):
    require(0 < len(data) <= binding.MAX_DOCUMENT, "the reliability CLI input exceeds its bound")
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), \
            patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(data))):
        code = binding.main([])
    rendered = stdout.getvalue()
    require(stderr.getvalue() == "" and rendered.count("\n") == 1
            and len(rendered.encode("utf-8")) <= 4096, "the reliability CLI diagnostic exceeds its contract")
    result = json.loads(rendered)
    require(all(result[key] is False for key in binding.FALSE_FIELDS), "a reliability authority field changed")
    require("snapshot" not in result and "binding" not in result, "the reliability CLI disclosed a report body")
    return code, result


PROBE = observation.CAPTURE_RULES + r'''
import contextlib
import copy
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

root, checkout, source, area = (Path(value).resolve() for value in sys.argv[1:5])
declared = json.load(sys.stdin)
scripts, inputs, scratch = root / "scripts", area / "inputs", area / "scratch"
library = Path(os.__file__).resolve().parent
assert sys.flags.isolated and sys.dont_write_bytecode
assert root == area / "skills/complex-work-orchestration"
assert source == area / "source" and not source.exists()
assert Path.cwd() == area / "home" == Path(os.environ["HOME"]).resolve()
assert Path(os.environ["TMPDIR"]).resolve() == scratch
assert not area.is_relative_to(checkout)
assert all(not Path(value).resolve().is_relative_to(checkout) for value in sys.path)
assert all(not Path(value).resolve().is_relative_to(source) for value in sys.path)
assert not any(name == "cwo_core" or name.startswith("cwo_core.") for name in sys.modules)
sys.path[:] = [value for value in sys.path if Path(value).resolve().is_relative_to(library)
               and not {"site-packages", "dist-packages"} & set(Path(value).parts)]
sys.path.insert(0, str(scripts))
tempfile.tempdir = str(scratch)
interpreter = {"path": sys.executable, "version": sys.version,
               "sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()}
initial_modules = set(sys.modules)
reads = {name: set() for name in ("installed", "input", "delivery", "scratch", "library")}
denied = dict.fromkeys(("read", "write", "mutation", "process-run", "process-Popen",
                        "process-audit", "network", "beads-run", "beads-structured",
                        "beads-create", "beads-link", "closure", "validator", "stage"), 0)
git_calls = dict.fromkeys(("process-run", "process-Popen", "process-audit"), 0)
capture_io = dict.fromkeys(("null_opens", "pipe_reads", "pipe_pairs"), 0)
cache_calls = dict.fromkeys(("cold", "warm"), 0)
positive_counts = dict.fromkeys(("cold-capture", "warm-capture", "known-descriptor"), 0)
command_controls_pending, command_control_operation, command_control_admitted = False, None, 0
command_control_counts = dict.fromkeys(("arguments", "environment", "directory"), 0)
descriptors, opening, active, current = {}, [], None, None
operations, outcomes = {}, {}
capture_depth, writes, mutations, editing = 0, 0, 0, False
real_open, real_dup, real_close, real_pipe = os.open, os.dup, os.close, os.pipe
real_run, real_popen = subprocess.run, subprocess.Popen
null_info = os.stat(os.devnull)
null_identity = (null_info.st_dev, null_info.st_ino, null_info.st_rdev)

class EffectRefused(RuntimeError):
    pass

def block(name):
    denied[name] += 1
    raise EffectRefused(name)

def descriptor_path(fd):
    saved = descriptors.get(fd)
    try:
        info = os.fstat(fd)
        present = os.stat(saved[0]) if saved is not None else None
    except OSError:
        block("read")
    if saved is None or saved[1:] != (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)):
        block("read")
    if (present.st_dev, present.st_ino, stat.S_IFMT(present.st_mode)) != saved[1:]:
        block("read")
    return saved[0]

def path_for(value, directory=None):
    if isinstance(value, int):
        return descriptor_path(value)
    alias = re.fullmatch(r"/proc/self/fd/(0|[1-9][0-9]*)", os.fsdecode(value))
    if alias is not None:
        return descriptor_path(int(alias[1]))
    path = Path(os.fsdecode(value))
    if directory not in (None, -1) and not path.is_absolute():
        path = path_for(directory) / path
    return Path(os.path.abspath(path))

def remember(fd, path):
    info = os.fstat(fd)
    descriptors[fd] = (path, info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
    return fd

def open_path(value, flags, *args, **kwargs):
    opening.append(path_for(value, kwargs.get("dir_fd")))
    try:
        return remember(real_open(value, flags, *args, **kwargs), opening[-1])
    finally:
        opening.pop()

def dup(fd):
    return remember(real_dup(fd), path_for(fd))

def close(fd):
    descriptors.pop(fd, None)
    return real_close(fd)

def pipe():
    if active is None:
        block("process-audit")
    pair = real_pipe()
    info = os.fstat(pair[0])
    active["pipes"][pair[0]] = (info.st_dev, info.st_ino)
    active["pipe_pairs"] += 1
    capture_io["pipe_pairs"] += 1
    return pair

def read_path(path, flags=0):
    directories = [("installed", root), ("input", inputs), ("library", library)]
    if current is not None:
        directories.append(("delivery", Path(current["root"])))
    if capture_depth:
        directories.append(("scratch", scratch))
    for name, directory in directories:
        if path.is_relative_to(directory) and not {"site-packages", "dist-packages"} & set(path.parts):
            reads[name].add(str(path))
            return
    if flags & os.O_DIRECTORY and any(directory.is_relative_to(path) for _, directory in directories):
        return
    block("read")

def edit_paths():
    repo = Path(declared["primary_root"])
    return {repo / "src/item.txt", repo / "src/EXAMPLE-later.txt"}

def write_path(path):
    global writes
    if not (capture_depth and path.is_relative_to(scratch)) and not (editing and path in edit_paths()):
        block("write")
    writes += 1

def mutate(event, args):
    global mutations
    if event in {"os.rename", "os.link"}:
        paths = (path_for(args[0], args[2]), path_for(args[1], args[3]))
    elif event == "os.symlink":
        block("mutation")
    else:
        directory = None if event == "os.truncate" else args[-1]
        paths = (path_for(args[0], directory),)
    permitted = capture_depth and all(path.is_relative_to(scratch) for path in paths)
    controlled = editing and event in {"os.remove", "os.chmod"} and all(path in edit_paths() for path in paths)
    if not permitted and not controlled:
        block("mutation")
    mutations += 1

def process(command, options, name):
    try:
        key = git_key(command, options.get("cwd"), options.get("env"), scratch,
                      declared["git_executables"], declared["git_configuration"], declared["git_environment"])
        executable = os.fsdecode(command[0])
        allowed = capture_depth > 0 and key in declared["git_commands"]
        allowed = allowed and executable_identity(executable) == declared["git_executables"][executable]
        if name == "process-run":
            allowed = (allowed and list(command)[1:] == ["--version"]
                       and set(options) == {"env", "stdin", "capture_output", "timeout", "check"}
                       and options["capture_output"] is True and options["check"] is False
                       and 0.1 <= options["timeout"] <= 10.0)
        else:
            allowed = (allowed and set(options) == {"env", "stdin", "stdout", "stderr"}
                       and options["stdout"] == subprocess.PIPE and options["stderr"] == subprocess.PIPE)
        allowed = allowed and options.get("stdin") == subprocess.DEVNULL
    except (TypeError, ValueError, OSError):
        allowed = False
    if not allowed:
        block(name)
    git_calls[name] += 1
    return key

def run(*args, **kwargs):
    process(args[0] if args else kwargs.get("args"), kwargs, "process-run")
    return real_run(*args, **kwargs)

def popen(*args, **kwargs):
    global active, command_control_admitted
    command = args[0] if args else kwargs.get("args")
    key = process(command, kwargs, "process-Popen")
    if active is not None:
        block("process-Popen")
    paired = command_controls_pending and list(command)[1:] != ["--version"]
    if paired:
        capture_command_controls(command, kwargs, key)
    context = {"argv": [os.fsdecode(value) for value in command], "env": dict(kwargs["env"]),
               "events": [], "null_opens": 0, "pipe_reads": 0, "pipe_pairs": 0, "pipes": {}}
    active = context
    try:
        child = real_popen(*args, **kwargs)
        assert context["events"] in (
            ["subprocess.Popen"], ["subprocess.Popen", "os.posix_spawn"],
            ["subprocess.Popen", "_posixsubprocess.fork_exec"])
        assert (context["null_opens"], context["pipe_reads"]) == (1, 2)
        assert context["pipe_pairs"] == (2 if context["events"][-1] == "os.posix_spawn" else 3)
        key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
        row = operations.setdefault(key_hash, {"operation_sha256": key_hash, "executable": context["argv"][0],
                                               "calls": 0, "sequences": {}})
        row["calls"] += 1
        sequence = "|".join(context["events"])
        row["sequences"][sequence] = row["sequences"].get(sequence, 0) + 1
        if paired:
            command_control_admitted += 1
        return child
    finally:
        active = None

def native_environment(values):
    pairs = [os.fsdecode(value).split("=", 1) for value in values]
    if any(len(pair) != 2 for pair in pairs) or len({pair[0] for pair in pairs}) != len(pairs):
        raise ValueError("EXAMPLE reliability native environment differs")
    return dict(pairs)

def launch(event, args):
    try:
        assert active is not None
        if event == "subprocess.Popen":
            assert not active["events"] and len(args) == 4 and args[2] is None
            executable, command, environment = args[0], args[1], args[3]
        else:
            assert active["events"] == ["subprocess.Popen"] and len(args) == 3
            if event == "os.posix_spawn":
                executable, command, environment = args
            else:
                assert event == "_posixsubprocess.fork_exec"
                assert [os.fsdecode(value) for value in args[0]] == [active["argv"][0]]
                executable, command, environment = active["argv"][0], args[1], native_environment(args[2])
        assert os.fsdecode(executable) == active["argv"][0]
        assert [os.fsdecode(value) for value in command] == active["argv"]
        assert environment == active["env"]
        assert active["null_opens"] == 1 and active["pipe_reads"] == 2
    except (AssertionError, TypeError, ValueError, OSError):
        block("process-audit")
    active["events"].append(event)
    git_calls["process-audit"] += 1

def null_open(flags):
    info = os.stat(os.devnull)
    if (active is None or active["events"] or active["null_opens"]
            or flags & ~os.O_CLOEXEC != os.O_RDWR or not stat.S_ISCHR(info.st_mode)
            or (info.st_dev, info.st_ino, info.st_rdev) != null_identity):
        block("write")
    active["null_opens"] += 1
    capture_io["null_opens"] += 1

def audit(event, args):
    if event == "open":
        if isinstance(args[0], int) and stat.S_ISFIFO(os.fstat(args[0]).st_mode):
            info = os.fstat(args[0])
            if (active is None or active["events"] or active["pipe_reads"] >= 2
                    or active["pipes"].get(args[0]) != (info.st_dev, info.st_ino)
                    or (args[2] or 0) & (os.O_WRONLY | os.O_RDWR)):
                block("read")
            active["pipe_reads"] += 1
            capture_io["pipe_reads"] += 1
            return
        path = opening[-1] if opening else path_for(args[0])
        flags = args[2] or 0
        if path == Path(os.devnull):
            null_open(flags)
        elif flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            write_path(path)
        else:
            read_path(path, flags)
    elif event in {"os.listdir", "os.scandir"}:
        read_path(path_for(args[0]))
    elif event in {"os.remove", "os.rmdir", "os.mkdir", "os.rename", "os.link",
                   "os.symlink", "os.chmod", "os.chown", "os.truncate", "os.utime"}:
        mutate(event, args)
    elif event in {"subprocess.Popen", "os.posix_spawn", "_posixsubprocess.fork_exec"}:
        launch(event, args)
    elif event in {"os.system", "os.exec", "os.spawn", "os.fork", "os.forkpty"}:
        block("process-audit")
    elif event.startswith("socket."):
        block("network")

profile_effects = {
    (str(scripts / relative), name): effect
    for relative, name, effect in (
        ("cwo_core/beads.py", "run_bd", "beads-run"),
        ("cwo_core/beads.py", "run_bd_structured", "beads-structured"),
        ("cwo_core/beads.py", "create_bead", "beads-create"),
        ("cwo_core/beads.py", "add_dependency", "beads-link"),
        ("close_bead_with_summary.py", "execute", "closure"),
        ("cwo_core/checked_command.py", "execute_checked_command", "validator"),
        ("cwo_core/stage_completion.py", "consume", "stage"),
    )
}
profile_names = frozenset(name for _, name in profile_effects)

def profile(frame, event, argument):
    if event != "call" or frame.f_code.co_name not in profile_names:
        return
    effect = profile_effects.get((frame.f_code.co_filename, frame.f_code.co_name))
    if effect is not None:
        block(effect)

sys.addaudithook(audit)
sys.setprofile(profile)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")

def note(name, status, result, exit_code=None):
    assert name not in outcomes
    outcomes[name] = {"name": name, "status": status, "exit_code": exit_code,
                      "result_sha256": hashlib.sha256(canonical(result)).hexdigest()}

def held(result):
    assert all(result[key] is False for key in binding.FALSE_FIELDS)
    assert {"W06", "#37", "W07", "M1a", "W05-holds", "W09-holds", "W08-holds"} <= set(result["remaining_open"])

def status(result):
    held(result)
    if result["errors"]:
        assert result["snapshot"] is None and result["binding"] is None
        assert not result["binding_consistent"] and not result["combined_observations_complete"]
        return "REFUSED"
    if result["binding_consistent"]:
        return "BOUND" if result["combined_observations_complete"] else "BOUND_INCOMPLETE"
    assert result["snapshot"] is not None
    return "OBSERVED" if result["combined_observations_complete"] else "OBSERVED_INCOMPLETE"

def document(path):
    path = Path(path)
    assert path.parent == inputs
    return json.loads(path.read_bytes())

@contextlib.contextmanager
def selected(context):
    global current
    assert current is None
    try:
        assert context["root"] in declared["roots"]
        assert type(context["bead"]) is dict
        assert not ci.candidate_errors(context["candidate"])
        rb.resolve_chain(context["baseline"], context["amendments"])
        current = context
    except (AssertionError, rb.RequirementBaselineError, KeyError, TypeError):
        current = None
    try:
        yield
    finally:
        current = None

def capture(*args, **kwargs):
    global capture_depth
    assert current is not None
    capture_depth += 1
    try:
        return native_capture(*args, **kwargs)
    finally:
        capture_depth -= 1

def selection(*args, **kwargs):
    before = dict(wc._GIT_CACHE)
    chosen = native_selection(*args, **kwargs)
    assert chosen is not None
    assert {**chosen.describe(), "identity": list(chosen.identity)} == declared["git_selected"]
    cache_calls["warm" if before.get(chosen.path) == chosen else "cold"] += 1
    return chosen

def invoke(mode, case):
    context = case["context"]
    raw = case["review"].encode("utf-8")
    with selected(context):
        if mode == "observe":
            return binding.observe(context)
        if mode == "prepare":
            return binding.prepare(context, raw, case["expected"])
        return binding.consume(case["prepared"], context, raw, case["expected"])

def cli(mode, case):
    envelope = {"record_type": binding.CLI_TYPE, "version": 1, "mode": mode, "context": case["context"]}
    if mode != "observe":
        envelope.update(raw_review=case["review"], expected=case["expected"])
    if mode == "check":
        envelope["prepared"] = case["prepared"]
    return cli_bytes(canonical(envelope), case["context"])

def cli_bytes(data, context):
    stdout, stderr = io.StringIO(), io.StringIO()
    with selected(context), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), \
            patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(data))):
        code = binding.main([])
    rendered = stdout.getvalue()
    assert stderr.getvalue() == ""
    assert len(rendered.encode("utf-8")) <= 4096 and rendered.count("\n") == 1
    result = json.loads(rendered)
    held(result)
    assert "snapshot" not in result and "binding" not in result
    return code, result

def malformed_cli(plan, context):
    path = Path(plan["path"])
    assert path.parent == inputs
    data = path.read_bytes()
    assert 0 < len(data) <= binding.MAX_DOCUMENT
    code, result = cli_bytes(data, context)
    assert code == 1 and result["binding_consistent"] is False
    assert result["combined_observations_complete"] is False
    assert result["snapshot_available"] is False and result["review_verdict"] is None
    assert result["errors"] == ["JSON parsing or serialization bounds were refused"]
    note(plan["name"], "REFUSED", result, code)

def exercise(plan):
    case = document(plan["path"])
    for mode in plan["modes"]:
        result = invoke(mode, case)
        actual_status = status(result)
        assert actual_status == plan["statuses"][mode]
        note(plan["name"] + "/library/" + mode, actual_status, result)
        if mode in plan["cli"]:
            code, summary = cli(mode, case)
            available = result["binding_consistent"] or result["snapshot"] is not None
            assert code == (0 if available and not result["errors"] else 1)
            assert summary["report_sha256"] == "sha256:" + hashlib.sha256(canonical(result)).hexdigest()
            assert summary == {**{key: result[key] for key in (
                *binding.FALSE_FIELDS, "binding_consistent", "combined_observations_complete",
                "review_verdict", "remaining_open", "errors")},
                "record_type": "cwo-combined-review-cli-diagnostic", "version": 1,
                "snapshot_available": result["snapshot"] is not None,
                "report_sha256": "sha256:" + hashlib.sha256(canonical(result)).hexdigest()}
            note(plan["name"] + "/cli/" + mode, actual_status, summary, code)

def components(case):
    context = case["context"]
    with selected(context):
        chain = rb.resolve_chain(context["baseline"], context["amendments"])
        check = ci.check_candidate(context["candidate"], root=context["root"], chain=chain, bead=context["bead"])
        artifact = final_review.observe(context["root"], context["baseline"], context["candidate"],
                                        context["bead"], context["amendments"])
        validator = validators.prepare(context["root"], context["baseline"], context["candidate"],
                                       context["bead"], context["validator_evidence"], context["amendments"])
        actual_artifact = artifacts.prepare(context["root"], context["baseline"], context["candidate"],
                                            context["bead"], context["amendments"])
    snapshot = case["expected"]["context"]["snapshot"]
    assert check == {
        "valid": True, "errors": [],
        "digest": ci.candidate_digest(context["candidate"]),
        "reference_line": ci.candidate_reference_line(chain["bead_id"], ci.candidate_digest(context["candidate"])),
    }
    assert snapshot["input_context"] == context
    assert snapshot["resolved_baseline"] == chain
    assert snapshot["criterion_inventory"] == chain["baseline"]["criteria"]
    assert snapshot["required_criterion_ids"] == rb.required_criterion_ids(chain["baseline"])
    assert artifact == snapshot["artifact_observation"]
    assert validator == snapshot["validator_observation"]
    assert actual_artifact == artifact["snapshot"]["artifact_report"]
    assert not artifact["artifact_observations_complete"] and not validator["observations_complete"]
    assert [entry["state"] for entry in snapshot["criteria"]] == [
        "PASSED", "OBSERVED_CONSISTENT", "NOT_APPLICABLE", "OBSERVED_CONSISTENT"]
    for name, result in (("baseline", chain), ("candidate", check), ("artifact", artifact),
                         ("validator", validator), ("artifact-predicate", actual_artifact)):
        note("mixed/component/" + name, "OBSERVED", result)

def delivery_changes(case):
    global editing
    path = Path(case["context"]["root"]) / "src/item.txt"
    extra = path.parent / "EXAMPLE-later.txt"
    with selected(case["context"]):
        original, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
    changes = (
        ("content", lambda: path.write_bytes(b"EXAMPLE later reliability content\n"),
         lambda: path.write_bytes(original)),
        ("mode", lambda: path.chmod(mode ^ 0o020), lambda: path.chmod(mode)),
        ("untracked", lambda: extra.write_bytes(b"EXAMPLE later reliability file\n"), lambda: extra.unlink()),
    )
    for name, change, restore in changes:
        try:
            editing = True
            change()
            editing = False
            result = invoke("check", case)
            assert status(result) == "REFUSED"
            note("delivery/" + name, "REFUSED", result)
        finally:
            editing = True
            restore()
            editing = False
        result = invoke("check", case)
        assert result == case["prepared"]
        note("restored/" + name, "BOUND", result)

def origins():
    records = []
    for name, module in list(sys.modules.items()):
        if name in initial_modules or not getattr(module, "__file__", None):
            continue
        path = Path(module.__file__).resolve()
        if path.is_relative_to(library) and not {"site-packages", "dist-packages"} & set(path.parts):
            continue
        assert path.is_relative_to(scripts)
        spec = module.__spec__
        assert Path(spec.origin).resolve() == path
        packages = [str(Path(value).resolve()) for value in getattr(module, "__path__", ())]
        locations = [str(Path(value).resolve()) for value in spec.submodule_search_locations or ()]
        assert packages == locations == ([str(path.parent)] if hasattr(module, "__path__") else [])
        assert str(path) in reads["installed"]
        records.append({"name": name, "path": str(path), "spec_origin": str(Path(spec.origin).resolve()),
                        "package_paths": packages, "spec_package_paths": locations,
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    assert not any(name == "tests" or name.startswith("tests.") for name in sys.modules)
    return sorted(records, key=lambda item: item["name"])

def control(name, call):
    before = dict(denied)
    try:
        call()
    except EffectRefused as error:
        assert error.args == (name,)
    else:
        raise AssertionError("EXAMPLE reliability guard missed its control")
    finally:
        sys.setprofile(profile)
    before[name] += 1
    assert denied == before

def capture_command_controls(command, options, key):
    global command_controls_pending, command_control_operation
    assert command_controls_pending and current is not None and capture_depth > 0 and active is None
    assert current["root"] in declared["roots"] and key in declared["git_commands"]
    assert "EXAMPLE_RELIABILITY" not in options["env"]
    command_controls_pending = False
    command_control_operation = hashlib.sha256(key.encode("utf-8")).hexdigest()
    context, depth = current, capture_depth
    before_calls, before_io, before_cache = dict(git_calls), dict(capture_io), dict(cache_calls)
    before_operations = copy.deepcopy(operations)
    variations = (
        ("arguments", [*command, "--EXAMPLE-unsupported"], dict(options)),
        ("environment", list(command), {
            **options, "env": {**options["env"], "EXAMPLE_RELIABILITY": "changed"}}),
        ("directory", [command[0], "-C", str(area / "home"), *command[3:]], dict(options)),
    )
    for name, changed, keywords in variations:
        control("process-Popen", lambda: subprocess.Popen(changed, **keywords))
        assert current is context and capture_depth == depth and active is None
        assert git_calls == before_calls and capture_io == before_io and cache_calls == before_cache
        assert operations == before_operations
        command_control_counts[name] += 1

def operation_delta(before):
    rows = []
    for key, row in operations.items():
        prior = before.get(key, {"calls": 0, "sequences": {}})
        calls = row["calls"] - prior["calls"]
        if calls:
            sequences = {name: count - prior["sequences"].get(name, 0)
                         for name, count in row["sequences"].items()
                         if count > prior["sequences"].get(name, 0)}
            rows.append({**row, "calls": calls, "sequences": sequences})
    return sorted(rows, key=lambda item: item["operation_sha256"])

def accepted_controls(case):
    global command_controls_pending
    context = case["context"]
    chain = rb.resolve_chain(context["baseline"], context["amendments"])
    with selected(context), patch.object(wc, "_GIT_CACHE", {}):
        command_controls_pending = True
        for name in ("cold-capture", "warm-capture"):
            actual = ci.capture_candidate(context["root"], chain=chain,
                                          base_commit=context["candidate"]["base_commit"], scope_paths=["src"])
            assert actual == context["candidate"]
            positive_counts[name] += 1
    assert not command_controls_pending and command_control_admitted == 1
    assert command_control_counts == dict.fromkeys(("arguments", "environment", "directory"), 1)
    fd = os.open(declared["plans"][0]["path"], os.O_PATH | os.O_CLOEXEC)
    try:
        reader = os.open(f"/proc/self/fd/{fd}", os.O_RDONLY | os.O_CLOEXEC)
        try:
            assert os.read(reader, 1) == b"{"
            positive_counts["known-descriptor"] += 1
        finally:
            os.close(reader)
    finally:
        os.close(fd)

def descriptor_controls():
    foreign = real_dup(sys.stdout.fileno())
    try:
        control("read", lambda: open(f"/proc/self/fd/{foreign}", "rb"))
    finally:
        os.close(foreign)
    fd = os.open(declared["plans"][0]["path"], os.O_RDONLY | os.O_CLOEXEC)
    replacement = os.open(declared["plans"][-1]["path"], os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.dup2(replacement, fd)
        control("read", lambda: open(f"/proc/self/fd/{fd}", "rb"))
    finally:
        os.close(replacement)
        os.close(fd)
    control("read", lambda: open(f"/proc/self/fd/{fd}", "rb"))

failure, phase, origin_records, image_result = None, "imports", [], None
with contextlib.ExitStack() as stack:
    for target, replacement in (("os.open", open_path), ("os.dup", dup), ("os.close", close),
                                ("os.pipe", pipe), ("subprocess.run", run), ("subprocess.Popen", popen)):
        stack.enter_context(patch(target, replacement))
    try:
        checker = importlib.import_module("check_installed_skill")
        actual_manifest = checker.build_manifest(root, strict=False)
        record_status = checker.record_check_status(root)
        if declared.get("image_only"):
            assert actual_manifest != declared["manifest"] and record_status["status"] == "record-drift"
            image_result = {"manifest_sha256": hashlib.sha256(canonical(actual_manifest)).hexdigest(),
                            "record": record_status}
        else:
            assert checker.REPO_ROOT == root and actual_manifest == declared["manifest"]
            assert record_status["status"] == "record-consistent"
            record = json.loads((root / ".cwo-install-manifest.json").read_bytes())
            assert record["source_dir"] == str(source)
            assert record["projection"] == declared["manifest"]["projection"]
            assert all(record[key] == declared["manifest"]["content_sha256"]
                       for key in ("source_content_sha256", "installed_content_sha256"))
            assert all(record[key] == declared["manifest"]["file_count"]
                       for key in ("source_file_count", "installed_file_count"))
            binding = importlib.import_module("prepare_combined_review_binding")
            final_review = importlib.import_module("prepare_final_review_binding")
            validators = importlib.import_module("prepare_validator_receipts")
            artifacts = importlib.import_module("prepare_artifact_acceptance")
            ci = importlib.import_module("cwo_core.candidate_identity")
            rb = importlib.import_module("cwo_core.requirement_baseline")
            wc = importlib.import_module("cwo_core.workspace_capture")
            beads = importlib.import_module("cwo_core.beads")
            closure = importlib.import_module("close_bead_with_summary")
            checked = importlib.import_module("cwo_core.checked_command")
            stage = importlib.import_module("cwo_core.stage_completion")
            assert not wc._GIT_CACHE
            assert list(wc.INERT_GIT_CONFIG) == declared["git_configuration"]
            assert wc._environment() == declared["git_environment"]
            native_capture, native_selection = wc.capture, wc.trusted_git
            stack.enter_context(patch.object(wc, "_GIT_CACHE", {}))
            stack.enter_context(patch.object(wc, "capture", capture))
            stack.enter_context(patch.object(wc, "trusted_git", selection))
            phase = "consumption"
            for plan in declared["plans"]:
                exercise(plan)
            primary = document(declared["plans"][0]["path"])
            for plan in declared["malformed_cli"]:
                malformed_cli(plan, primary["context"])
            components(primary)
            if declared["full"]:
                delivery_changes(primary)
            phase = "origins"
            origin_records = origins()
            assert all(hashlib.sha256(Path(item["path"]).read_bytes()).hexdigest() == item["sha256"]
                       for item in declared["inputs"] if Path(item["path"]).parent == inputs)
            assert not any(denied.values())
            assert cache_calls["cold"] > 0 and cache_calls["warm"] > 0
    except BaseException as error:
        failure = {"phase": phase, "type": type(error).__name__}
    measured, measured_git = dict(denied), dict(git_calls)
    measured_io = {"writes": writes, "mutations": mutations, **capture_io}
    measured_operations = json.loads(json.dumps(operations))
    measured_cache = dict(cache_calls)
    measured_reads = {name: len(paths) for name, paths in reads.items()}
    if not declared.get("image_only") and "primary" in globals():
        probes = [
            ("read", lambda: open(checkout / "EXAMPLE_BLOCKED", "rb")),
            ("read", lambda: open(source / "EXAMPLE_BLOCKED", "rb")),
            ("write", lambda: open(root / "EXAMPLE_BLOCKED", "w")),
            ("write", lambda: open(inputs / "EXAMPLE_BLOCKED", "w")),
            ("write", lambda: open(Path(declared["primary_root"]) / "src/item.txt", "w")),
            ("mutation", lambda: os.mkdir(area / "home/EXAMPLE_BLOCKED")),
            ("process-run", lambda: subprocess.run(["EXAMPLE_NEVER_RUN"])),
            ("process-Popen", lambda: subprocess.Popen(["EXAMPLE_NEVER_RUN"])),
            ("process-audit", lambda: sys.audit("subprocess.Popen", None, None, None, None)),
            ("process-audit", lambda: os.system("EXAMPLE_NEVER_RUN")),
            ("network", lambda: socket.socket()),
            ("beads-run", lambda: beads.run_bd(["EXAMPLE_NEVER_RUN"])),
            ("beads-structured", lambda: beads.run_bd_structured(
                ["EXAMPLE_NEVER_RUN"], directory=area, database="EXAMPLE_UNUSED", actor="EXAMPLE_ACTOR")),
            ("beads-create", lambda: beads.create_bead("EXAMPLE_NEVER_CREATED")),
            ("beads-link", lambda: beads.add_dependency("EXAMPLE_FIRST", "EXAMPLE_LAST")),
            ("closure", lambda: closure.execute(None)),
            ("validator", lambda: checked.execute_checked_command({})),
            ("stage", lambda: stage.consume(None, None, "EXAMPLE-unit", {})),
            ("process-run", lambda: subprocess.run(["git", "-C", declared["primary_root"], "status"])),
            ("write", lambda: os.open(os.devnull, os.O_RDWR)),
            ("process-audit", lambda: sys.audit("os.posix_spawn", declared["git"],
                                               [declared["git"], "--version"], declared["git_environment"])),
            ("process-audit", lambda: sys.audit("_posixsubprocess.fork_exec",
                                               [os.fsencode(declared["git"])], [declared["git"], "--version"], [])),
        ]
        try:
            accepted_controls(primary)
            descriptor_controls()
            for name, call in probes:
                control(name, call)
        except BaseException as error:
            if failure is None:
                failure = {"phase": "controls", "type": type(error).__name__}
sys.setprofile(None)
ok = failure is None and not any(measured.values())
print(json.dumps({
    "ok": ok, "failure": failure, "effects": measured, "git_calls": measured_git,
    "capture_io": {name: measured_io[name] for name in capture_io},
    "writes": measured_io["writes"], "mutations": measured_io["mutations"], "reads": measured_reads,
    "operations": sorted(measured_operations.values(), key=lambda item: item["operation_sha256"]),
    "cache_calls": measured_cache, "positive_counts": positive_counts,
    "control_effects": {name: denied[name] - measured[name] for name in denied},
    "control_io": {"writes": writes - measured_io["writes"], "mutations": mutations - measured_io["mutations"]},
    "command_controls": {"operation_sha256": command_control_operation, "admitted": command_control_admitted,
                         "refused": command_control_counts},
    "control_capture": {
        "git_calls": {name: git_calls[name] - measured_git[name] for name in git_calls},
        "capture_io": {name: capture_io[name] - measured_io[name] for name in capture_io},
        "cache_calls": {name: cache_calls[name] - measured_cache[name] for name in cache_calls},
        "operations": operation_delta(measured_operations),
    },
    "inputs": declared["inputs"], "origins": origin_records, "interpreter": interpreter,
    "outcomes": sorted(outcomes.values(), key=lambda item: item["name"]), "image_result": image_result,
}, sort_keys=True))
raise SystemExit(0 if ok else 1)
'''


def checked_cleanups(case):
    require(case.doCleanups(), "nested fixture cleanup failed")


class InstalledCombinedReviewConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        seed = cls("test_installed_combined_review_lifecycle_without_source")
        cls.addClassCleanup(checked_cleanups, seed)
        seed._prepare_install()
        seed.real_install()
        cls.seed_target = seed.install.target
        cls.seed_record = (cls.seed_target / RECORD).read_bytes()
        cls.seed_snapshot_sha256 = digest(image.snapshot(cls.seed_target))
        cls.seed_root_mode = cls.seed_target.lstat().st_mode
        cls.addClassCleanup(cls._verify_seed)
        shutil.rmtree(seed.source)
        require(not seed.source.exists(), "the seed source remains available")
        print("CWO_INSTALLED_COMBINED_REVIEW_SEED " + json.dumps({
            "schema": "cwo-installed-combined-review-seed-v1",
            "installer_returncode": seed.last_install_returncode,
            "record_sha256": hashlib.sha256(cls.seed_record).hexdigest(),
            "snapshot_sha256": cls.seed_snapshot_sha256, "root_mode": cls.seed_root_mode,
            "manifest_sha256": digest(seed.expected),
        }, sort_keys=True), flush=True)

    @classmethod
    def _verify_seed(cls):
        before = image.snapshot(cls.seed_target)
        require((digest(before), cls.seed_target.lstat().st_mode) == (
            cls.seed_snapshot_sha256, cls.seed_root_mode), "the installed combined-review seed changed")
        return before

    def _prepare_install(self):
        self.install = image.InstallerProjectionTests(
            "test_fresh_install_is_the_projection_and_its_resources_are_usable")
        self.addCleanup(self.cleanup_install)
        self.install.setUp()
        self.source = self.install.copy_source()
        require(not self.install.tmp.resolve().is_relative_to(image.ROOT.resolve()),
                "the disposable installation overlaps the checkout")
        self.inputs, self.scratch = self.install.tmp / "inputs", self.install.tmp / "scratch"
        self.inputs.mkdir()
        self.scratch.mkdir()
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        for key in ("CODEX_HOME", "CODEX_SKILLS_DIR", "PYTHONPATH", "PYTHONHOME",
                    "PYTHONSTARTUP", "BASH_ENV", "ENV"):
            self.env.pop(key, None)
        self.env.update(HOME=str(self.install.tmp / "home"), TMPDIR=str(self.scratch),
                        PYTHONDONTWRITEBYTECODE="1",
                        SKILL_VALIDATOR=str(self.install.tmp / "EXAMPLE_NO_VALIDATOR.py"))
        self.expected = image.checker.build_manifest(self.source)
        require({entry["path"]: entry["kind"] for entry in self.expected["entries"]} == image.REQUIRED,
                "the complete projection entry inventory differs")

    def setUp(self):
        self._prepare_install()
        self._copy_seed_install()
        prepare_replacement(self)

    def _copy_seed_install(self):
        before = self._verify_seed()
        shutil.copytree(self.seed_target, self.install.target)
        require(image.snapshot(self.install.target) == before
                and self.install.target.lstat().st_mode == self.seed_root_mode,
                "the private installed copy differs in bytes or modes")
        require(not os.path.samefile(self.seed_target, self.install.target), "the private root shares its inode")
        for relative in before:
            require(not os.path.samefile(self.seed_target / relative, self.install.target / relative),
                    "a private installed entry shares its inode")
        path = self.install.target / RECORD
        require(path.read_bytes() == self.seed_record, "the copied installation record differs")
        record = json.loads(self.seed_record)
        require(not Path(record["source_dir"]).exists(), "the original seed source remains available")
        # The checker validates source_dir as metadata only and never follows it.
        # Keep the genuine seed receipt; change only this private copy's coordinate.
        record["source_dir"] = str(self.source)
        path.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
        require(json.loads(path.read_bytes()) == record, "the private source-coordinate rebind differs")
        self.assert_image(self.install.target, self.expected)
        self.initial_image = {"kind": "private-seed-copy", "installer_returncode": None,
                              "root_mode": self.install.target.lstat().st_mode,
                              "seed_record_sha256": hashlib.sha256(self.seed_record).hexdigest(),
                              "private_record_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def cleanup_install(self):
        temporary = getattr(self.install, "_tmp", None)
        try:
            checked_cleanups(self.install)
        except BaseException as primary:
            try:
                if temporary is not None:
                    temporary.cleanup()
            except BaseException as secondary:
                raise primary from secondary
            raise
        if temporary is not None:
            temporary.cleanup()

    def run_install(self, **extra):
        return parent_call("install", self.install.run_installer, source=self.source,
                           extra_env={**self.env, **extra})

    def run_check(self, source=None, phase="installed-check"):
        source = self.source if source is None else source
        native_run = subprocess.run

        def private_run(*args, **kwargs):
            kwargs.setdefault("cwd", self.install.tmp / "home")
            kwargs.setdefault("env", self.env)
            return native_run(*args, **kwargs)

        with patch("subprocess.run", side_effect=private_run):
            return parent_call(phase, self.install.run_checker, "--source-dir", str(source),
                               "--installed-dir", str(self.install.target), "--check", source=source)

    def assert_image(self, root, expected):
        require(image.checker.build_manifest(root) == expected, "the complete installed manifest differs")
        record = json.loads((root / RECORD).read_bytes())
        require(record["version"] == 2 and record["status"] == "current", "the install record differs")
        require(record["source_dir"] == str(self.source.resolve()), "the source identity differs")
        require(record["projection"] == expected["projection"], "the projection identity differs")
        require(all(record[key] == expected["content_sha256"]
                    for key in ("source_content_sha256", "installed_content_sha256")), "the content identity differs")
        require(all(record[key] == expected["file_count"]
                    for key in ("source_file_count", "installed_file_count")), "the complete file count differs")
        require(not (root / "tests").exists(), "source tests entered the installed image")

    def real_install(self):
        result = self.run_install()
        require(result.returncode == 0, process_identity("install", result))
        self.last_install_returncode = result.returncode
        self.assert_image(self.install.target, self.expected)
        result = self.run_check()
        require(result.returncode == 0, process_identity("installed-check", result))

    @contextlib.contextmanager
    def capture_recording(self):
        self.git_commands, self.git_executables = set(), {}
        self.git_environment = wc._environment()
        self.git_configuration = list(wc.INERT_GIT_CONFIG)
        fixed = {os.path.realpath(path) for path in wc.TRUSTED_GIT_PATHS}
        native_selection, native_popen = wc.trusted_git, subprocess.Popen
        self.selection_counts = dict.fromkeys(("cold", "warm"), 0)

        def selection(*args, **kwargs):
            before = dict(wc._GIT_CACHE)
            chosen = native_selection(*args, **kwargs)
            require(chosen is not None, "the real local Git selector refused")
            selected = {**chosen.describe(), "identity": list(chosen.identity)}
            require(selected == getattr(self, "git_selected", selected), "the selected Git identity changed")
            self.git_selected, self.git = selected, chosen.path
            self.selection_counts["warm" if before.get(chosen.path) == chosen else "cold"] += 1
            return chosen

        def popen(*args, **kwargs):
            command = args[0] if args else kwargs.get("args")
            executable = os.fsdecode(command[0])
            if executable in fixed:
                identity = observation.executable_identity(executable)
                require(identity == self.git_executables.setdefault(executable, identity),
                        "the observed executable changed")
                key = observation.git_key(command, kwargs.get("cwd"), kwargs.get("env"), self.scratch,
                                          fixed, self.git_configuration, self.git_environment)
                self.git_commands.add(key)
            return native_popen(*args, **kwargs)

        with patch.object(wc, "_GIT_CACHE", {}), patch.object(wc, "trusted_git", side_effect=selection), \
                patch("subprocess.Popen", side_effect=popen):
            yield

    def new_fixture(self, variant="passed", **kwargs):
        example = examples.CombinedReviewBindingTests(
            "test_real_mixed_positive_retains_whole_reports_and_no_authority")
        self.addCleanup(checked_cleanups, example)
        workspaces = self.install.tmp / "EXAMPLE-fixture-workspaces"
        workspaces.mkdir(mode=0o700, exist_ok=True)
        native_workspace = examples.vf.TempGit

        def allocate_workspace(case):
            with patch.object(tempfile, "tempdir", str(workspaces)):
                return native_workspace(case)

        with patch.object(examples.vf, "TempGit", allocate_workspace):
            example.begin(variant, **kwargs)
        self.fixtures.append(example)
        return example

    def expected_status(self, result):
        require(all(result[key] is False for key in binding.FALSE_FIELDS), "an authority field changed")
        if result["errors"]:
            require(result["snapshot"] is None and result["binding"] is None
                    and result["binding_consistent"] is False
                    and result["combined_observations_complete"] is False, "a refusal retained applicability")
            return "REFUSED"
        if result["binding_consistent"]:
            return "BOUND" if result["combined_observations_complete"] else "BOUND_INCOMPLETE"
        require(result["snapshot"] is not None, "an observation has no snapshot")
        return "OBSERVED" if result["combined_observations_complete"] else "OBSERVED_INCOMPLETE"

    def expect(self, name, status, result, exit_code=None):
        require(name not in self.expected_outcomes, "an outcome name is duplicated")
        self.expected_outcomes[name] = {"name": name, "status": status, "exit_code": exit_code,
                                        "result_sha256": digest(result)}

    def add_case(self, name, context, *, complete=True, refuse=False, verdict="APPROVE",
                 modes=("prepare",), cli=(), review_change=None, expectation_change=None, suffix=b""):
        observed = binding.observe(context) if not refuse or "observe" in modes else None
        if observed is not None and not refuse:
            require(not observed["errors"], "the real source observation refused")
            require(observed["combined_observations_complete"] is complete, "source completeness differs")
        snapshot = observed["snapshot"] if observed is not None and observed["snapshot"] is not None else \
            self.primary_case["expected"]["context"]["snapshot"]
        review_context = {"review_id": "EXAMPLE-combined-review",
                          "reviewer": "EXAMPLE unauthenticated reliability reviewer",
                          "verdict": verdict, "snapshot": copy.deepcopy(snapshot)}
        review = {"record_type": binding.REVIEW_TYPE, "version": 1, "context": copy.deepcopy(review_context),
                  "findings": [], "summary": "EXAMPLE reliability review; all authority remains held."}
        expected = {"record_type": binding.EXPECTATION_TYPE, "version": 1, "context": review_context}
        if review_change is not None:
            review_change(review)
        raw = canonical(review)
        expected["raw_review_sha256"] = "sha256:" + hashlib.sha256(raw).hexdigest()
        if expectation_change is not None:
            expectation_change(expected)
        raw += suffix
        prepared = binding.prepare(context, raw, expected)
        wanted = "REFUSED" if refuse else "BOUND" if complete else "BOUND_INCOMPLETE"
        require(self.expected_status(prepared) == wanted, "the declared source binding outcome differs")
        saved = self.primary_case["prepared"] if refuse else prepared
        case = {"context": context, "review": raw.decode("utf-8"), "expected": expected, "prepared": saved}
        path = self.inputs / (name + ".json")
        path.write_bytes(canonical(case))
        statuses = {}
        for mode in modes:
            if mode == "observe":
                result = observed
            elif mode == "prepare":
                result = prepared
            else:
                result = binding.consume(saved, context, raw, expected)
            statuses[mode] = self.expected_status(result)
            self.expect(name + "/library/" + mode, statuses[mode], result)
            if mode in cli:
                code = 0 if not result["errors"] and (
                    result["binding_consistent"] or result["snapshot"] is not None) else 1
                self.expect(name + "/cli/" + mode, statuses[mode], cli_summary(result), code)
        self.plans.append({"name": name, "path": str(path), "modes": list(modes),
                           "cli": list(cli), "statuses": statuses})
        return case

    def prepare_inputs(self, full):
        self.fixtures, self.plans, self.expected_outcomes = [], [], {}
        self.malformed_plans = []
        git_env = {**self.env, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "LC_ALL": "C"}
        with patch.dict(os.environ, self.env, clear=True), patch.dict(examples.vf.ENV, git_env, clear=True), \
                patch.object(tempfile, "tempdir", str(self.scratch)), self.capture_recording():
            self.primary = self.new_fixture(additive=True)
            self.primary_case = self.add_case("mixed", self.primary.context(),
                                             modes=("observe", "prepare", "check"), cli=("observe", "prepare", "check"))
            self.component_expectations()
            if full:
                self.incomplete_cases()
                self.review_cases()
                self.prerequisite_case()
                self.drift_expectations()
                self.malformed_cli_cases()
            else:
                self.add_case("raw-bytes", self.primary.context(), refuse=True, suffix=b"\n")
        require(all(self.selection_counts.values()), "cold or warm source selection was not observed")
        version = observation.git_key([self.git, "--version"], None, self.git_environment, self.scratch,
                                      self.git_executables, self.git_configuration, self.git_environment)
        require(version in self.git_commands, "the real cold version query is missing")

    def component_expectations(self):
        context = self.primary.context()
        chain = rb.resolve_chain(context["baseline"], context["amendments"])
        check = ci.check_candidate(context["candidate"], root=context["root"], chain=chain, bead=context["bead"])
        artifact = examples.final_review.observe(context["root"], context["baseline"], context["candidate"],
                                                context["bead"], context["amendments"])
        validator = examples.validators.prepare(context["root"], context["baseline"], context["candidate"],
                                               context["bead"], context["validator_evidence"], context["amendments"])
        predicate = examples.final_review.artifacts.prepare(context["root"], context["baseline"], context["candidate"],
                                                            context["bead"], context["amendments"])
        snapshot = self.primary_case["expected"]["context"]["snapshot"]
        require(snapshot["artifact_observation"] == artifact and snapshot["validator_observation"] == validator,
                "the combined snapshot did not retain both real reports")
        for name, result in (("baseline", chain), ("candidate", check), ("artifact", artifact),
                             ("validator", validator), ("artifact-predicate", predicate)):
            self.expect("mixed/component/" + name, "OBSERVED", result)

    def incomplete_cases(self):
        for variant in ("failed", "refused"):
            example = self.new_fixture(variant)
            self.add_case("receipt-" + variant, example.context(), complete=False, verdict="REQUEST_CHANGES")
        missing = copy.deepcopy(self.primary.context())
        missing["validator_evidence"] = []
        self.add_case("receipt-missing", missing, complete=False, verdict="ABSTAIN",
                      modes=("prepare", "check"), cli=("prepare",))
        self.add_case("incomplete-approve", missing, complete=False, refuse=True)
        unrelated = copy.deepcopy(self.primary.context())
        unrelated["validator_evidence"][0] = self.primary.wrapper("EXAMPLE-validator", "additional")
        self.add_case("receipt-unrelated", unrelated, complete=False, verdict="REJECT")
        for name, field, value in (
            ("baseline", "baseline_digest", "sha256:" + "0" * 64),
            ("candidate", "candidate_digest", "sha256:" + "1" * 64),
            ("stdout", "result.diagnostics.stdout", "EXAMPLE different reliability output\n"),
            ("spec", "result.spec_sha256", "0" * 64),
            ("source", "spec.source", "print('EXAMPLE different reliability output')\n"),
            ("unrun", "result.execution_started", False),
            ("numeric", "result.exit_code", False),
        ):
            context = copy.deepcopy(self.primary.context())
            target = context["validator_evidence"][0]
            parts = field.split(".")
            for part in parts[:-1]:
                target = target[part]
            target[parts[-1]] = value
            self.add_case("receipt-" + name, context, complete=False, verdict="REQUEST_CHANGES")
        extra = (
            examples.vf.criterion("EXAMPLE-service", "EXAMPLE service reliability remains unobserved."),
            examples.vf.criterion("EXAMPLE-prose", "EXAMPLE prose reliability remains unobserved.", "artifact"),
            examples.vf.criterion("EXAMPLE-gate", "EXAMPLE independent reliability review remains required.", "review-gate"),
        )
        unsupported = self.new_fixture(extra=extra)
        self.add_case("unsupported", unsupported.context(), complete=False, verdict="REQUEST_CHANGES")
        self.add_case("unsupported-approve", unsupported.context(), complete=False, refuse=True)

    def review_cases(self):
        context = self.primary.context()
        self.add_case("raw-bytes", context, refuse=True, suffix=b"\n", cli=("prepare",))
        self.add_case("wrong-hash", context, refuse=True, expectation_change=lambda value: value.update(
            raw_review_sha256="sha256:" + "0" * 64))
        self.add_case("wrong-context", context, refuse=True, review_change=lambda value: value["context"].update(
            reviewer="EXAMPLE different unauthenticated reliability reviewer"))
        self.add_case("artifact-only", context, refuse=True, review_change=lambda value: value.update(
            record_type="cwo-experimental-final-review"))
        self.add_case("review-version", context, refuse=True, review_change=lambda value: value.update(version=True))
        blocker = {"id": "EXAMPLE-blocker", "blocking": True, "state": "OPEN",
                   "text": "EXAMPLE unresolved reliability finding."}
        self.add_case("blocker", context, refuse=True, review_change=lambda value: value.update(findings=[blocker]))
        omitted = copy.deepcopy(context)
        omitted["baseline"]["criteria"].pop(0)
        self.add_case("omitted-baseline", omitted, refuse=True)
        replaced = copy.deepcopy(context)
        replaced["baseline"]["criteria"][0]["expected_outcome"] = "EXAMPLE replacement reliability obligation."
        self.add_case("replaced-baseline", replaced, refuse=True)
        for name, value in (("context-version", True), ("context-type", 2)):
            changed = copy.deepcopy(context)
            changed["version" if name == "context-version" else "record_type"] = value
            self.add_case(name, changed, refuse=True, modes=("observe", "prepare"), cli=("observe",))

    def prerequisite_case(self):
        context = copy.deepcopy(self.primary.context())
        context["validator_evidence"] = [{"EXAMPLE-values": [0] * 10000, "EXAMPLE-padding": ""}]
        padding = binding.MAX_DOCUMENT - len(binding._encode(context)) - 1024
        require(padding > 0, "the real producer boundary fixture cannot fit")
        context["validator_evidence"][0]["EXAMPLE-padding"] = "x" * padding
        require(len(binding._encode(context)) < binding.MAX_DOCUMENT, "the compact boundary input exceeds its limit")
        document = {**context, "record_type": examples.validators.INPUT_TYPE}
        refused = examples.validators.prepare_document(document)
        require(bool(refused["errors"]) and refused["bindings"] == {}, "the real component prerequisite did not refuse")
        self.add_case("component-prerequisite", context, refuse=True,
                      modes=("observe", "prepare", "check"), cli=("observe",))

    def drift_expectations(self):
        context = self.primary.context()
        case = self.primary_case
        path, extra = self.primary.repo / "src/item.txt", self.primary.repo / "src/EXAMPLE-later.txt"
        original, mode = path.read_bytes(), path.stat().st_mode & 0o7777
        changes = (
            ("content", lambda: path.write_bytes(b"EXAMPLE later reliability content\n"), lambda: path.write_bytes(original)),
            ("mode", lambda: path.chmod(mode ^ 0o020), lambda: path.chmod(mode)),
            ("untracked", lambda: extra.write_bytes(b"EXAMPLE later reliability file\n"), lambda: extra.unlink()),
        )
        before = image.snapshot(self.primary.repo)
        for name, change, restore in changes:
            try:
                change()
                result = binding.consume(case["prepared"], context, case["review"].encode("utf-8"), case["expected"])
                require(self.expected_status(result) == "REFUSED", "a real delivery change retained the saved review")
                self.expect("delivery/" + name, "REFUSED", result)
            finally:
                restore()
            result = binding.consume(case["prepared"], context, case["review"].encode("utf-8"), case["expected"])
            require(result == case["prepared"], "the restored source control differs")
            self.expect("restored/" + name, "BOUND", result)
        require(image.snapshot(self.primary.repo) == before, "source expectation production changed delivery bytes or modes")

    def declared(self, full):
        return {"manifest": self.expected, "plans": self.plans, "full": full,
                "malformed_cli": self.malformed_plans,
                "roots": [str(example.repo) for example in self.fixtures], "primary_root": str(self.primary.repo),
                "inputs": self.input_identities, "git": self.git, "git_selected": self.git_selected,
                "git_executables": self.git_executables, "git_commands": sorted(self.git_commands),
                "git_environment": self.git_environment, "git_configuration": self.git_configuration}

    def child(self, declared, phase="installed-consumer"):
        result = parent_call(
            phase, subprocess.run,
            [sys.executable, "-I", "-B", "-S", "-c", PROBE, str(self.install.target),
             str(image.ROOT.resolve()), str(self.source), str(self.install.tmp)],
            cwd=self.install.tmp / "home", env=self.env, input=json.dumps(declared),
            capture_output=True, text=True, check=False, timeout=180)
        require(len(result.stdout.encode("utf-8")) <= 131072, process_identity(phase, result))
        try:
            report = json.loads(result.stdout)
        except (ValueError, TypeError):
            raise AssertionError(process_identity(phase, result)) from None
        require(result.returncode == 0 and type(report) is dict and report.get("ok") is True,
                process_identity(phase, result))
        require(report["failure"] is None and not any(report["effects"].values()), "the installed child observed a refusal")
        return report

    def consume_without_source(self, scenario, full, rows=None):
        self.prepare_inputs(full)
        self.source_manifest = (image.checker.build_manifest(self.source) if rows is None
                                else rows[0]["metadata"]["source_manifest"])
        paths = list(self.inputs.glob("*.json"))
        for example in self.fixtures:
            paths.extend(path for path in example.repo.rglob("*") if path.is_file())
        self.input_identities = [{"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                                 for path in sorted(set(paths))]
        require(0 < len(self.input_identities) <= 512, "the retained input inventory exceeds its bound")
        require(self.source == self.install.tmp / "source" and self.source.resolve() != image.ROOT.resolve(),
                "the private source deletion target differs")
        shutil.rmtree(self.source)
        before = image.snapshot(self.install.tmp)
        deliveries = [image.snapshot(example.repo) for example in self.fixtures]
        require(image.snapshot(self.scratch) == {}, "the initial capture scratch is not empty")
        declared = self.declared(full)
        report = self.child(declared)
        require(image.snapshot(self.install.tmp) == before, "installed consumption changed a retained private path")
        require([image.snapshot(example.repo) for example in self.fixtures] == deliveries,
                "installed consumption did not restore delivery bytes and modes")
        if full:
            self.image_refusals(declared, report)
            self.retention_controls(report)
        for row in rows or [None]:
            self.retain_evidence(scenario if row is None else row["row_id"], report, row)

    def image_refusals(self, declared, report):
        target = self.install.target
        before = image.snapshot(target)
        paths = ("scripts/prepare_combined_review_binding.py", "scripts/prepare_final_review_binding.py",
                 "scripts/prepare_validator_receipts.py")
        for relative in paths:
            path = target / relative
            data, mode = path.read_bytes(), path.stat().st_mode & 0o7777
            for kind in ("missing", "modified"):
                try:
                    if kind == "missing":
                        path.unlink()
                    else:
                        path.write_bytes(data + b"\n# EXAMPLE disposable reliability change.\n")
                    self.image_refusal(declared, report, relative + "/" + kind)
                finally:
                    path.write_bytes(data)
                    path.chmod(mode)
                require(image.snapshot(target) == before, "the dependency refusal fixture was not restored")
        extra = target / "scripts/EXAMPLE-extra.py"
        try:
            extra.write_text("# EXAMPLE disposable reliability inventory entry.\n", encoding="utf-8")
            self.image_refusal(declared, report, "inventory")
        finally:
            extra.unlink()
        require(image.snapshot(target) == before, "the inventory refusal fixture was not restored")

    def image_refusal(self, declared, report, label):
        expected = {"manifest_sha256": digest(image.checker.build_manifest(self.install.target, strict=False)),
                    "record": image.checker.record_check_status(self.install.target)}
        require(expected["record"]["status"] == "record-drift", "the real retained-record checker missed image drift")
        actual = self.child({**declared, "image_only": True}, "installed-image")
        require(actual["image_result"] == expected, "the installed image refusal differs")
        name = "image/" + label
        self.expect(name, "REFUSED", expected)
        report["outcomes"].append({"name": name, "status": "REFUSED", "exit_code": None,
                                   "result_sha256": digest(actual["image_result"])})
        report["outcomes"].sort(key=lambda item: item["name"])

    def malformed_cli_cases(self):
        context = self.primary_case["context"]
        envelope = {"record_type": binding.CLI_TYPE, "version": 1, "mode": "observe", "context": context}
        valid = canonical(envelope)
        require(binding._decode(valid) == envelope, "the reliability CLI positive parser input differs")
        code, summary = parent_cli(valid)
        require(code == 0 and digest(summary) == self.expected_outcomes["mixed/cli/observe"]["result_sha256"],
                "the real reliability CLI positive differs from the source observation")
        cases = (
            ("duplicate", b'{"version":1,' + valid[1:]),
            ("non-object", b"[]"),
            ("numeric", canonical({**envelope, "version": 1.5})),
        )
        for label, data in cases:
            require(0 < len(data) <= binding.MAX_DOCUMENT, "the malformed reliability CLI input exceeds its bound")
            try:
                binding._decode(data)
            except binding.PreparationError as error:
                require(str(error) == "JSON parsing or serialization bounds were refused",
                        "the reliability parser refused for an unrelated reason")
                refused = binding._refuse(binding._report(), str(error))
            else:
                raise AssertionError("EXAMPLE reliability malformed parser control was accepted")
            require(self.expected_status(refused) == "REFUSED"
                    and len(canonical(refused)) <= 4096, "the reliability parser refusal is not bounded")
            code, summary = parent_cli(data)
            require(code == 1 and summary == cli_summary(refused),
                    "the real reliability CLI refusal differs from the independent parser result")
            name = "malformed/cli/" + label
            path = self.inputs / ("malformed-cli-" + label + ".json")
            path.write_bytes(data)
            self.expect(name, "REFUSED", summary, code)
            self.malformed_plans.append({"name": name, "path": str(path)})

    def validate_report(self, report):
        validate_guard_counts(report)
        require(report["inputs"] == self.input_identities, "retained input identities differ")
        require(report["outcomes"] == sorted(self.expected_outcomes.values(), key=lambda item: item["name"]),
                "retained outcome names, statuses, exits or hashes differ")
        interpreter = {"path": sys.executable, "version": sys.version,
                       "sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()}
        require(report["interpreter"] == interpreter, "the actual interpreter identity differs")
        require(image.checker.build_manifest(self.install.target) == self.expected,
                "the full installed inventory differs before retention")
        for item in self.input_identities:
            require(hashlib.sha256(Path(item["path"]).read_bytes()).hexdigest() == item["sha256"],
                    "an actual retained input changed")
        self.validate_origins(report["origins"])
        self.validate_capture(report)
        require(report["positive_counts"] == {"cold-capture": 1, "warm-capture": 1, "known-descriptor": 1},
                "accepted capture or descriptor controls differ")
        require(report["control_io"]["writes"] > 0 and report["control_io"]["mutations"] > 0,
                "accepted scratch controls did not observe real I/O")
        require(all(report["reads"][key] > 0 for key in ("installed", "input", "delivery", "scratch")),
                "a declared reliability read class was not observed")

    def validate_origins(self, records):
        require(0 < len(records) <= 128, "the installed origin inventory exceeds its bound")
        names = {item["name"] for item in records}
        require(len(names) == len(records), "an installed origin name is duplicated")
        required = {"prepare_combined_review_binding", "prepare_final_review_binding", "prepare_validator_receipts",
                    "prepare_artifact_acceptance", "check_installed_skill", "close_bead_with_summary",
                    "cwo_core", "cwo_core.candidate_identity", "cwo_core.requirement_baseline",
                    "cwo_core.checked_command", "cwo_core.workspace_capture", "cwo_core.git_store",
                    "cwo_core.beads", "cwo_core.stage_completion", "cwo_core.util"}
        require(required <= names, "an actual installed dependency origin is missing")
        files = {item["path"]: item["sha256"] for item in self.expected["files"]}
        for item in records:
            path = Path(item["path"])
            require(path.is_absolute() and path.is_relative_to(self.install.target / "scripts"),
                    "a helper loaded outside the installed scripts")
            require(item["spec_origin"] == str(path), "a helper spec origin differs")
            packages = [str(path.parent)] if item["name"] == "cwo_core" else []
            require(item["package_paths"] == item["spec_package_paths"] == packages, "a package origin differs")
            require(item["sha256"] == files[path.relative_to(self.install.target).as_posix()]
                    == hashlib.sha256(path.read_bytes()).hexdigest(), "an installed helper hash differs")

    def validate_capture(self, report):
        expected = {hashlib.sha256(key.encode("utf-8")).hexdigest() for key in self.git_commands}
        self.validate_native_capture(report, expected, complete=True)
        controls = report["control_capture"]
        self.validate_native_capture(controls, expected, complete=False)
        command = report["command_controls"]
        require(type(command) is dict and set(command) == {"operation_sha256", "admitted", "refused"},
                "the reliability command control record differs")
        require(type(command["admitted"]) is int and command["admitted"] == 1,
                "the unchanged reliability command was not admitted")
        require(type(command["refused"]) is dict
                and set(command["refused"]) == {"arguments", "environment", "directory"}
                and all(type(value) is int and value == 1 for value in command["refused"].values()),
                "the reliability command mutation controls differ")
        require(command["operation_sha256"] in {item["operation_sha256"] for item in controls["operations"]},
                "the admitted reliability control has no real native launch")

    def validate_native_capture(self, report, expected, *, complete):
        operations = report["operations"]
        observed = {item["operation_sha256"] for item in operations}
        require(observed <= expected and len(operations) == len(observed) <= 8
                and (not complete or observed == expected), "the complete observed Git operation inventory differs")
        calls, events, pairs = 0, 0, 0
        sequences = {"subprocess.Popen", "subprocess.Popen|os.posix_spawn",
                     "subprocess.Popen|_posixsubprocess.fork_exec"}
        for item in operations:
            require(item["executable"] in self.git_executables and type(item["calls"]) is int and item["calls"] > 0,
                    "an observed executable is undeclared")
            require(set(item["sequences"]) <= sequences
                    and all(type(count) is int and count > 0 for count in item["sequences"].values()),
                    "a native launch sequence differs")
            require(sum(item["sequences"].values()) == item["calls"], "launch sequence counts differ")
            calls += item["calls"]
            events += sum(len(sequence.split("|")) * count for sequence, count in item["sequences"].items())
            pairs += sum((2 if sequence.endswith("|os.posix_spawn") else 3) * count
                         for sequence, count in item["sequences"].items())
        require(set(report["git_calls"]) == {"process-run", "process-Popen", "process-audit"}
                and all(type(count) is int and count > 0 for count in report["git_calls"].values()),
                "the reliability process counter inventory or types differ")
        require(calls == report["git_calls"]["process-Popen"]
                and events == report["git_calls"]["process-audit"], "process and native audit counts differ")
        require(report["capture_io"] == {"null_opens": calls, "pipe_reads": calls * 2, "pipe_pairs": pairs}
                and all(type(count) is int for count in report["capture_io"].values()),
                "null-device or pipe reliability observations differ")
        require(set(report["cache_calls"]) == {"cold", "warm"}
                and all(type(count) is int and count > 0 for count in report["cache_calls"].values()),
                "cold or warm reliability selection counts differ")
        require(calls == 2 * sum(report["cache_calls"].values()) + report["git_calls"]["process-run"]
                and report["git_calls"]["process-run"] == report["cache_calls"]["cold"],
                "the reliability capture, cache and version-query totals differ")

    def retention_controls(self, report):
        self.validate_report(report)
        for changed in self.retention_refusals(report):
            self.refuse_retention(changed)

    def retention_refusals(self, report):
        for field in ("inputs", "outcomes", "origins"):
            changed = copy.deepcopy(report)
            changed[field] = []
            yield changed
        for name in GUARD_NAMES:
            changed = copy.deepcopy(report)
            for field in ("effects", "control_effects"):
                del changed[field][name]
            yield changed
        for field in ("effects", "control_effects"):
            changed = copy.deepcopy(report)
            changed[field]["EXAMPLE-extra-guard"] = 1
            yield changed
            for name in GUARD_NAMES:
                original = report[field][name]
                values = (False, True, float(original), -1, original + 1, None, "EXAMPLE-count")
                if field == "control_effects":
                    values += (0,)
                for value in values:
                    changed = copy.deepcopy(report)
                    changed[field][name] = value
                    yield changed
            for value in (None, False, [], {}, "EXAMPLE-unavailable-guards", list(report[field].items())):
                changed = copy.deepcopy(report)
                changed[field] = value
                yield changed
            changed = copy.deepcopy(report)
            del changed[field]
            yield changed

    def refuse_retention(self, report):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(AssertionError) as caught:
            self.retain_evidence("fresh", report)
        require(stdout.getvalue() == "", "a refused reliability retention control emitted evidence")
        require(len(str(caught.exception).encode("utf-8")) <= 4096,
                "a reliability retention refusal exceeded its diagnostic bound")

    def _lifecycle_metadata(self):
        return {"transition": getattr(self, "transition", {"installer_returncode": None}),
                "source_manifest": image.checker.build_manifest(self.source)}

    def retain_evidence(self, scenario, report, row=None):
        metadata = ({"transition": getattr(self, "transition", {"installer_returncode": None}),
                     "source_manifest": self.source_manifest} if row is None else row["metadata"])
        require(scenario in ("fresh", "replacement", "activation-rollback", "term-rollback"),
                "the retained scenario is undeclared")
        self.validate_report(report)
        installed = image.checker.build_manifest(self.install.target)
        source_manifest = metadata["source_manifest"]
        files = {item["path"]: item["sha256"] for item in source_manifest["files"]}
        source_names = {Path(item["path"]).relative_to(self.install.target).as_posix()
                        for item in report["origins"]}
        source_names.update(("SECURITY.md", "scripts/install.sh", image.PROJECTION))
        helpers = [{"path": str(self.source / name), "sha256": files[name]} for name in sorted(source_names)]
        modules = (sys.modules[__name__], examples, examples.af, examples.vf, image, observation, rollback_fixture)
        tests = [{"path": str(Path(module.__file__).resolve()),
                  "sha256": hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()} for module in modules]
        installation = [{"path": str(self.install.target / name),
                         "sha256": hashlib.sha256((self.install.target / name).read_bytes()).hexdigest()}
                        for name in (RECORD, "SECURITY.md", "scripts/install.sh", image.PROJECTION)]
        evidence = {
            "schema": SCHEMA, "scenario": scenario, "inputs": self.input_identities,
            "shared_product_flow_sha256": digest(report),
            "origins": report["origins"], "outcomes": report["outcomes"], "interpreter": report["interpreter"],
            "source": {"root": str(self.source), "manifest_sha256": digest(source_manifest),
                       "helpers": helpers, "tests": tests},
            "installation": installation,
            "manifests": {"expected_sha256": digest(self.expected), "installed_sha256": digest(installed),
                          "content_sha256": installed["content_sha256"], "file_count": installed["file_count"],
                          "projection_sha256": installed["projection"]["sha256"]},
            "capture": {"selected": self.git_selected, "executables": self.git_executables,
                        "operations": report["operations"], "calls": report["git_calls"],
                        "cache_calls": report["cache_calls"], "io": report["capture_io"]},
            **{key: report[key] for key in ("effects", "reads", "writes", "mutations", "positive_counts",
                                           "control_effects", "control_io", "command_controls", "control_capture")},
            "initial_image": self.initial_image,
            "transition": metadata["transition"],
        }
        data = canonical(evidence)
        require(len(data) <= 65536, "the normalized evidence exceeds its byte bound")
        print(MARKER + data.decode("utf-8"), flush=True)

    def test_installed_combined_review_lifecycle_without_source(self):
        require(self.install.leftovers() == [], "a fresh install left staging or backup paths")
        shared = RestoredInstalledRows(self, self._lifecycle_metadata)
        shared.exercise_rollbacks(())
        shared.retain()
        with self.subTest(row="fresh"):
            self.consume_without_source("fresh", True, rows=shared.rows)
        with self.subTest(row="replacement"):
            self.replacement_case.replacement_row()

    def replacement_row(self):
        marker = self.install.target / "EXAMPLE_REPLACEMENT"
        marker.write_bytes(b"EXAMPLE controlled reliability replacement marker\n")
        marker.chmod(0o640)
        previous = image.snapshot(self.install.target)
        self.real_install()
        backups = list(self.install.backups.glob(f"{image.SKILL}.prev.*"))
        require(len(backups) == 1 and image.snapshot(backups[0]) == previous,
                "the controlled replacement backup differs in bytes or modes")
        require(not marker.exists() and not list(self.install.skills.glob(f".{image.SKILL}.stage.*")),
                "the replacement marker or stage remains active")
        self.transition = {"installer_returncode": self.last_install_returncode,
                           "previous_sha256": digest(previous), "backup": str(backups[0]),
                           "backup_sha256": digest(image.snapshot(backups[0]))}
        self.consume_without_source("replacement", False)

    def test_activation_rollback_installed_combined_review_without_source(self):
        self.rollback("activation")

    def test_term_rollback_installed_combined_review_without_source(self):
        self.rollback("term")

    def rollback(self, mode):
        previous, source_before = image.snapshot(self.install.target), image.snapshot(self.source)
        security = self.source / "SECURITY.md"
        security.write_bytes(security.read_bytes() + b"\nEXAMPLE disposable reliability rollback stage.\n")
        replacement = image.checker.build_manifest(self.source)
        source_after = image.snapshot(self.source)
        require(set(source_before) == set(source_after)
                and {name for name in source_before if source_before[name] != source_after[name]} == {"SECURITY.md"},
                "the controlled rollback source change differs")
        require(image.checker.compare_manifests(self.expected, replacement)["changed_files"] == ["SECURITY.md"],
                "the controlled staged manifest differs")
        witness, event = self.install.tmp / "EXAMPLE-witness", self.install.tmp / "EXAMPLE-event"
        shim = self.install.shims / "mv"
        self.addCleanup(shim.unlink, missing_ok=True)
        self.install.write_shim("mv", rollback_fixture.MV_SHIM)
        try:
            result = self.run_install(
                CWO_TEST_INTERRUPT=mode, CWO_TEST_TARGET=str(self.install.target),
                CWO_TEST_SKILLS=str(self.install.skills), CWO_TEST_BACKUPS=str(self.install.backups),
                CWO_TEST_SKILL=image.SKILL, CWO_TEST_WITNESS=str(witness), CWO_TEST_EVENT=str(event))
        finally:
            shim.unlink(missing_ok=True)
        require(result.returncode == 143 if mode == "term" else result.returncode != 0,
                process_identity("install", result))
        if mode == "activation":
            require(f"error: could not activate staged install at {self.install.target}" in result.stderr.splitlines(),
                    "the real activation refusal is missing")
        require(f"Restored the previous install at {self.install.target}" in result.stderr.splitlines(),
                "the real restoration diagnostic is missing")
        require(image.snapshot(self.install.target) == previous and image.snapshot(self.source) == source_after,
                "rollback did not preserve the restored bytes, modes and staged source")
        require(self.install.leftovers() == [], "rollback left a stage or backup path")
        paths = event.read_text(encoding="utf-8").splitlines()
        require(len(paths) == 2, "the rollback witness event has an unsupported shape")
        stage, backup = (Path(value) for value in paths)
        require(stage.parent == self.install.skills and stage.name.startswith(f".{image.SKILL}.stage."),
                "the recorded stage identity differs")
        require(backup.parent == self.install.backups and backup.name.startswith(f"{image.SKILL}.prev."),
                "the recorded backup identity differs")
        self.assert_image(witness, replacement)
        self.assert_image(self.install.target, self.expected)
        check = self.run_check(source=self.install.target, phase="restored-check")
        require(check.returncode == 0, process_identity("restored-check", check))
        self.transition = {"installer_returncode": result.returncode, "mode": mode,
                           "stderr": stream_identity(result.stderr), "previous_sha256": digest(previous),
                           "restored_sha256": digest(image.snapshot(self.install.target)),
                           "source_before_sha256": digest(source_before), "source_after_sha256": digest(source_after),
                           "stage": str(stage), "backup": str(backup), "event": str(event),
                           "event_sha256": hashlib.sha256(event.read_bytes()).hexdigest(),
                           "witness": str(witness), "witness_manifest_sha256": digest(replacement),
                           "witness_snapshot_sha256": digest(image.snapshot(witness))}
        shutil.rmtree(witness)
        self.consume_without_source(mode + "-rollback", False)



class ParentCombinedReviewReliabilityControls(unittest.TestCase):


    def test_deadlines_retain_only_bounded_metadata(self):
        for phase in PHASES:
            timeout = subprocess.TimeoutExpired(
                ["EXAMPLE_COMMAND_MUST_NOT_APPEAR"], 1, output=b"EXAMPLE_OUTPUT_MUST_NOT_APPEAR",
                stderr=b"EXAMPLE_ERROR_MUST_NOT_APPEAR")
            stdout = io.StringIO()
            with self.subTest(phase=phase), contextlib.redirect_stdout(stdout), \
                    patch.object(subprocess, "run", side_effect=timeout):
                with self.assertRaises(AssertionError) as caught:
                    parent_call(phase, subprocess.run, ["EXAMPLE_COMMAND_MUST_NOT_APPEAR"])
            rendered = "".join(traceback.format_exception(caught.exception))
            metadata = json.loads(str(caught.exception))
            require(metadata["phase"] == phase and metadata["type"] == "TimeoutExpired"
                    and metadata["command_count"] == 1, "the deadline metadata differs")
            require(metadata["stdout"] == stream_identity(timeout.output)
                    and metadata["stderr"] == stream_identity(timeout.stderr), "deadline stream identities differ")
            require(metadata["command_sha256"] == digest(["EXAMPLE_COMMAND_MUST_NOT_APPEAR"]),
                    "the deadline command identity differs")
            for text in ("EXAMPLE_COMMAND_MUST_NOT_APPEAR", "EXAMPLE_OUTPUT_MUST_NOT_APPEAR",
                         "EXAMPLE_ERROR_MUST_NOT_APPEAR", PROBE, MARKER):
                require(text not in rendered and text not in stdout.getvalue(), "a deadline disclosed fixture content")
            require(len(rendered) < 4000 and caught.exception.__suppress_context__,
                    "the original deadline chain was retained")

    def test_parent_boundary_preserves_nonzero_and_unrelated_errors(self):
        completed = subprocess.CompletedProcess(["EXAMPLE_NEVER_RUN"], 23, "", "")
        with patch.object(subprocess, "run", return_value=completed):
            require(parent_call("install", subprocess.run, []) is completed, "a real nonzero result was replaced")
        failure = RuntimeError("EXAMPLE unrelated reliability failure")
        with patch.object(subprocess, "run", side_effect=failure):
            with self.assertRaises(RuntimeError) as caught:
                parent_call("installed-consumer", subprocess.run, [])
        require(caught.exception is failure, "an unrelated failure was replaced")

        case = InstalledCombinedReviewConsumerTests("runTest")
        case.install = unittest.TestCase()
        case.install.addCleanup(case.fail, "EXAMPLE deliberate nested cleanup failure")
        with self.assertRaisesRegex(AssertionError, "nested fixture cleanup failed"):
            case.cleanup_install()
        primary = RuntimeError("EXAMPLE primary cleanup failure")
        secondary = OSError("EXAMPLE temporary-directory cleanup failure")
        case.install = SimpleNamespace(doCleanups=lambda: True,
                                       _tmp=SimpleNamespace(cleanup=lambda: None))
        with patch.object(case.install, "doCleanups", side_effect=primary), \
                patch.object(case.install._tmp, "cleanup", side_effect=secondary):
            with self.assertRaises(RuntimeError) as caught:
                case.cleanup_install()
        require(caught.exception is primary and caught.exception.__cause__ is secondary,
                "a secondary cleanup failure replaced the primary")


    def test_command_controls_use_selected_capture_and_refuse_before_native_launch(self):
        fixture = examples.CombinedReviewBindingTests(
            "test_real_mixed_positive_retains_whole_reports_and_no_authority")
        self.addCleanup(checked_cleanups, fixture)
        fixture.begin(additive=True)
        context = fixture.context()
        area = Path("/EXAMPLE-reliability-area")
        scratch, executable = area / "scratch", "/EXAMPLE-reliability-git"
        environment, identity = {"LC_ALL": "C"}, [1, 2, 3, 4]
        command = [executable, "-C", str(scratch / ("cwo-inspect-" + "0" * 16) / "tree"),
                   "ls-files", "--stage", "-v", "--sparse", "--full-name", "-z"]
        options = {"env": {**environment, "GIT_DIR": str(Path(command[2]).parent / "git"),
                           "GIT_WORK_TREE": command[2]}, "stdin": subprocess.DEVNULL,
                   "stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
        namespace = {
            "contextlib": contextlib, "copy": copy, "hashlib": hashlib, "json": json,
            "os": os, "Path": Path, "re": re, "ci": ci, "rb": rb, "area": area, "scratch": scratch,
            "sys": SimpleNamespace(setprofile=lambda value: None), "profile": lambda *args: None,
            "subprocess": SimpleNamespace(PIPE=subprocess.PIPE, DEVNULL=subprocess.DEVNULL),
            "executable_identity": lambda path: identity, "current": None, "capture_depth": 0, "active": None,
            "denied": dict.fromkeys(GUARD_NAMES, 0),
            "git_calls": dict.fromkeys(("process-run", "process-Popen", "process-audit"), 0),
            "capture_io": dict.fromkeys(("null_opens", "pipe_reads", "pipe_pairs"), 0),
            "cache_calls": dict.fromkeys(("cold", "warm"), 0), "operations": {},
            "command_controls_pending": True, "command_control_operation": None, "command_control_admitted": 0,
            "command_control_counts": dict.fromkeys(("arguments", "environment", "directory"), 0),
            "LISTINGS": (tuple(command[3:]), ("ls-files", "-z", "--others", "--ignored",
                                             "--exclude-standard", "--directory", "--full-name")),
            "declared": {"roots": [context["root"]], "git_executables": {executable: identity},
                         "git_configuration": [], "git_environment": environment},
        }
        names = {"EffectRefused", "block", "git_key", "process", "popen", "control",
                 "selected", "capture", "capture_command_controls"}
        declarations = [node for node in ast.parse(PROBE).body
                        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names]
        exec(compile(ast.Module(body=declarations, type_ignores=[]),
                     "EXAMPLE_reliability_command_controls", "exec"), namespace)
        key = namespace["git_key"](command, None, options["env"], scratch, {executable: identity}, [], environment)
        namespace["declared"]["git_commands"] = [key]
        admitted, launches = object(), []

        def native_popen(actual, **keywords):
            require(actual == command and keywords == options, "a refused reliability command reached native launch")
            require(namespace["current"] is context and namespace["capture_depth"] > 0,
                    "the admitted reliability command lacks selected capture context")
            launches.append((list(actual), copy.deepcopy(keywords)))
            namespace["active"].update(events=["subprocess.Popen"], null_opens=1, pipe_reads=2, pipe_pairs=3)
            return admitted

        namespace["real_popen"] = native_popen
        namespace["subprocess"].Popen = namespace["popen"]
        namespace["native_capture"] = lambda: namespace["popen"](command, **options)
        with namespace["selected"](context):
            require(namespace["current"] is context, "the reliability context was not validated")
            require(namespace["capture"]() is admitted, "the valid reliability command was not admitted")
        require(launches == [(command, options)] and namespace["git_calls"]["process-Popen"] == 1,
                "a refused reliability command reached the native stand-in")
        require(namespace["command_control_counts"] == {"arguments": 1, "environment": 1, "directory": 1},
                "an independent reliability command variation was not refused")
        expected = dict.fromkeys(GUARD_NAMES, 0)
        expected["process-Popen"] = 3
        require(namespace["denied"] == expected, "the reliability command guard deltas differ")
        require(namespace["command_control_admitted"] == 1 and not namespace["command_controls_pending"],
                "the unchanged reliability command was not paired with its refusals")
        require(namespace["command_control_operation"] == hashlib.sha256(key.encode("utf-8")).hexdigest(),
                "the reliability command control used a different operation")
        require(namespace["current"] is None and namespace["capture_depth"] == 0 and namespace["active"] is None,
                "the reliability capture context did not clear")

    def test_profile_dispatch_preserves_exact_boundaries(self):
        scripts = Path("/EXAMPLE-installed/scripts")
        expected = {
            (str(scripts / "cwo_core/beads.py"), "run_bd"): "beads-run",
            (str(scripts / "cwo_core/beads.py"), "run_bd_structured"): "beads-structured",
            (str(scripts / "cwo_core/beads.py"), "create_bead"): "beads-create",
            (str(scripts / "cwo_core/beads.py"), "add_dependency"): "beads-link",
            (str(scripts / "close_bead_with_summary.py"), "execute"): "closure",
            (str(scripts / "cwo_core/checked_command.py"), "execute_checked_command"): "validator",
            (str(scripts / "cwo_core/stage_completion.py"), "consume"): "stage",
        }
        counts = dict.fromkeys(expected.values(), 0)
        failure = RuntimeError("EXAMPLE reliability profile control")

        def refuse(effect):
            counts[effect] += 1
            raise failure

        namespace = {"scripts": scripts, "block": refuse}
        start = PROBE.index("\nprofile_effects = ") + 1
        end = PROBE.index("\nsys.addaudithook(audit)", start)
        exec(compile(PROBE[start:end], "EXAMPLE_reliability_profile", "exec"), namespace)
        require(namespace["profile_effects"] == expected, "the reliability profile table differs")
        require(namespace["profile_names"] == frozenset(name for _, name in expected),
                "the reliability profile function names differ")
        profile = namespace["profile"]
        for event in ("return", "c_call", "c_return", "c_exception"):
            require(profile(None, event, None) is None, "a non-call reliability event was inspected")
        frame = SimpleNamespace(f_code=SimpleNamespace(co_name="EXAMPLE_unrelated"))
        require(profile(frame, "call", None) is None, "an unrelated reliability name inspected its filename")
        filenames = sorted({filename for filename, _ in expected} | {str(scripts / "EXAMPLE-unrelated.py")})
        names = sorted({name for _, name in expected} | {"EXAMPLE_unrelated"})
        for filename in filenames:
            for name in names:
                frame = SimpleNamespace(f_code=SimpleNamespace(co_filename=filename, co_name=name))
                before = dict(counts)
                effect = expected.get((filename, name))
                if effect is None:
                    require(profile(frame, "call", None) is None, "an unrelated reliability pair was refused")
                else:
                    with self.assertRaises(RuntimeError) as caught:
                        profile(frame, "call", None)
                    require(caught.exception is failure, "the reliability profile replaced an unrelated exception")
                    before[effect] += 1
                require(counts == before, "the reliability profile counter differs")
        require(counts == dict.fromkeys(expected.values(), 1), "a reliability profile boundary control is missing")



if __name__ == "__main__":
    unittest.main()


# Reliability qualification remains deferred until corrected producer composition,
# applicable offline checks and a separate current independent source review.
# This preparation declares no source approval, installed qualification or closure.
