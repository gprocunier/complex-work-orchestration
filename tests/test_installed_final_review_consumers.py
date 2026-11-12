"""Installed final-review reliability evidence in disposable directories."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests.installed_consumer_fixtures import RestoredInstalledRows, prepare_replacement
from tests import test_artifact_acceptance_preparation as delivery_fixture
from tests import test_final_review_binding_preparation as review_fixture
from tests import test_install_projection as fixture
from tests.test_installed_numeric_rollback import MV_SHIM
from cwo_core import workspace_capture as capture_fixture

RECORD = ".cwo-install-manifest.json"
NEW = b"EXAMPLE reliable renamed delivery.\n"
CAPTURE_RULES = r'''
LISTINGS = (
    ("ls-files", "--stage", "-v", "--sparse", "--full-name", "-z"),
    ("ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory", "--full-name"),
)

def executable_identity(path):
    info = os.stat(path)
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns]

def git_key(command, cwd, environment, scratch, executables, configuration, base_environment):
    if not isinstance(command, (list, tuple)) or not command:
        raise ValueError("EXAMPLE reliability capture requires local Git arguments")
    words = [os.fsdecode(value) for value in command]
    if words[0] not in executables or cwd is not None or not isinstance(environment, dict):
        raise ValueError("EXAMPLE reliability capture identity is unregistered")
    environment = dict(environment)
    if words[1:] == ["--version"]:
        if environment != base_environment:
            raise ValueError("EXAMPLE reliability version environment differs")
    else:
        if len(words) < 4 or words[1] != "-C":
            raise ValueError("EXAMPLE reliability capture requires its private repository")
        tree = Path(words[2])
        if str(tree) != words[2] or tree.parent.parent != scratch or tree.name not in ("tree", "mirror"):
            raise ValueError("EXAMPLE reliability capture repository differs")
        if not re.fullmatch(r"cwo-inspect-[0-9a-f]{16}", tree.parent.name):
            raise ValueError("EXAMPLE reliability capture scratch name differs")
        if words[3:3 + len(configuration)] != list(configuration) or tuple(words[3 + len(configuration):]) not in LISTINGS:
            raise ValueError("EXAMPLE reliability capture listing differs")
        wanted = {**base_environment, "GIT_DIR": str(tree.parent / "git"), "GIT_WORK_TREE": str(tree)}
        if environment != wanted:
            raise ValueError("EXAMPLE reliability capture environment differs")
        words[2] = str(scratch / "EXAMPLE_CAPTURE" / tree.name)
        environment = {**base_environment, "GIT_DIR": str(scratch / "EXAMPLE_CAPTURE/git"),
                       "GIT_WORK_TREE": words[2]}
    return json.dumps([words, None, environment], sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
'''
_CAPTURE_NAMESPACE = {"os": os, "Path": Path, "re": re, "json": json}
exec(CAPTURE_RULES, _CAPTURE_NAMESPACE)
git_key = _CAPTURE_NAMESPACE["git_key"]
executable_identity = _CAPTURE_NAMESPACE["executable_identity"]


def parent_call(phase, call, *args, **kwargs):
    try:
        return call(*args, **kwargs)
    except subprocess.TimeoutExpired:
        diagnostic = {"phase": phase, "status": "failed", "type": "TimeoutExpired"}
        raise AssertionError(json.dumps(diagnostic, sort_keys=True)) from None


def process_metadata(phase, result):
    streams = [result.stdout or "", result.stderr or ""]
    return json.dumps({
        "phase": phase, "returncode": result.returncode,
        "stdout_bytes": len(streams[0].encode("utf-8")),
        "stdout_sha256": hashlib.sha256(streams[0].encode("utf-8")).hexdigest(),
        "stderr_bytes": len(streams[1].encode("utf-8")),
        "stderr_sha256": hashlib.sha256(streams[1].encode("utf-8")).hexdigest(),
    }, sort_keys=True)


PROBE = CAPTURE_RULES + r'''
import contextlib
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
from unittest.mock import patch

root, checkout, source, area = (Path(value).resolve() for value in sys.argv[1:5])
declared = json.load(sys.stdin)
scripts, inputs, scratch = root / "scripts", area / "inputs", area / "scratch"
repo, library = Path(declared["repo"]).resolve(), Path(os.__file__).resolve().parent
assert sys.flags.isolated and sys.dont_write_bytecode
assert root == area / "skills/complex-work-orchestration"
assert source == area / "source" and not source.exists()
assert repo.is_dir() and not repo.is_relative_to(source) and not area.is_relative_to(checkout)
assert Path.cwd() == area / "home" == Path(os.environ["HOME"]).resolve()
assert Path(os.environ["TMPDIR"]).resolve() == scratch
assert all(not Path(value).resolve().is_relative_to(checkout) for value in sys.path)
assert all(not Path(value).resolve().is_relative_to(source) for value in sys.path)
assert not any(name == "cwo_core" or name.startswith("cwo_core.") for name in sys.modules)
sys.path[:] = [value for value in sys.path if Path(value).resolve().is_relative_to(library)
               and not {"site-packages", "dist-packages"} & set(Path(value).parts)]
sys.path.insert(0, str(scripts))
tempfile.tempdir = str(scratch)
initial_modules = set(sys.modules)
reads = {name: set() for name in ("installed", "input", "delivery", "scratch", "library")}
denied = dict.fromkeys(("read", "write", "mutation", "process-run", "process-Popen",
                        "process-audit", "network", "beads-run", "beads-structured",
                        "beads-create", "beads-link", "closure"), 0)
git_calls = dict.fromkeys(("process-run", "process-Popen", "process-audit"), 0)
writes, mutations, editing, cli_calls, refusals = 0, 0, False, 0, 0
descriptors, opening, active = {}, [], None
operations, outcomes = {}, {}
cache_calls = dict.fromkeys(("cold", "warm"), 0)
capture_io = dict.fromkeys(("null_opens", "pipe_reads", "pipe_pairs"), 0)
real_open, real_dup, real_run, real_popen = os.open, os.dup, subprocess.run, subprocess.Popen
real_close, real_pipe = os.close, os.pipe
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
        current = os.stat(saved[0]) if saved is not None else None
    except OSError:
        block("read")
    if saved is None or saved[1:] != (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)):
        block("read")
    if (current.st_dev, current.st_ino, stat.S_IFMT(current.st_mode)) != saved[1:]:
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
    path = path_for(value, kwargs.get("dir_fd"))
    opening.append(path)
    try:
        return remember(real_open(value, flags, *args, **kwargs), path)
    finally:
        opening.pop()

def dup(fd):
    path = path_for(fd)
    return remember(real_dup(fd), path)

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
    for name, directory in (("installed", root), ("input", inputs), ("delivery", repo),
                            ("scratch", scratch), ("library", library)):
        if path.is_relative_to(directory) and not {"site-packages", "dist-packages"} & set(path.parts):
            reads[name].add(str(path))
            return
    if flags & os.O_DIRECTORY and any(directory.is_relative_to(path)
                                      for directory in (root, inputs, repo, scratch, library)):
        return
    block("read")

def write_path(path):
    global writes
    if not path.is_relative_to(scratch) and not (editing and path == repo / "src/new.txt"):
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
    if any(not path.is_relative_to(scratch) for path in paths):
        block("mutation")
    mutations += 1

def process(command, options, name):
    try:
        key = git_key(command, options.get("cwd"), options.get("env"), scratch,
                      declared["git_executables"], declared["git_configuration"], declared["git_environment"])
        executable = os.fsdecode(command[0])
        allowed = key in declared["git_commands"] and executable_identity(executable) == declared["git_executables"][executable]
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
    global active
    command = args[0] if args else kwargs.get("args")
    key = process(command, kwargs, "process-Popen")
    if active is not None:
        block("process-Popen")
    context = {"argv": [os.fsdecode(value) for value in command], "env": dict(kwargs["env"]),
               "events": [], "null_opens": 0, "pipe_reads": 0, "pipe_pairs": 0, "pipes": {}}
    active = context
    try:
        child = real_popen(*args, **kwargs)
        assert context["events"] in (
            ["subprocess.Popen"], ["subprocess.Popen", "os.posix_spawn"],
            ["subprocess.Popen", "_posixsubprocess.fork_exec"])
        assert (context["null_opens"], context["pipe_reads"]) == (1, 2)
        expected_pairs = 2 if context["events"][-1] == "os.posix_spawn" else 3
        assert context["pipe_pairs"] == expected_pairs
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        row = operations.setdefault(digest, {"operation_sha256": digest, "executable": context["argv"][0],
                                             "calls": 0, "sequences": {}})
        row["calls"] += 1
        sequence = "|".join(context["events"])
        row["sequences"][sequence] = row["sequences"].get(sequence, 0) + 1
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
            or flags & ~os.O_CLOEXEC != os.O_RDWR
            or not stat.S_ISCHR(info.st_mode)
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
            return
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
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

def profile(frame, event, argument):
    if event != "call":
        return
    filename, name = frame.f_code.co_filename, frame.f_code.co_name
    if filename == str(scripts / "cwo_core/beads.py"):
        effect = {"run_bd": "beads-run", "run_bd_structured": "beads-structured",
                  "create_bead": "beads-create", "add_dependency": "beads-link"}.get(name)
        if effect is not None:
            block(effect)
    if filename == str(scripts / "close_bead_with_summary.py") and name == "execute":
        block("closure")

# Register named reliability observations before installed imports or calls.
sys.addaudithook(audit)
sys.setprofile(profile)

def document(path):
    path = Path(path)
    assert path.parent == inputs
    return json.loads(path.read_bytes())

def held(result):
    assert all(result[key] is False for key in binding.FALSE_FIELDS)
    assert {"W06", "#37", "W07", "M1a"} <= set(result["remaining_open"])

def note(name, status, result):
    assert name not in outcomes
    data = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    outcomes[name] = {"name": name, "status": status, "result_sha256": hashlib.sha256(data).hexdigest()}

def identities(records):
    return [{"path": item["path"], "sha256": hashlib.sha256(Path(item["path"]).read_bytes()).hexdigest()}
            for item in records]

def selection(*args, **kwargs):
    before = dict(wc._GIT_CACHE)
    chosen = native_selection(*args, **kwargs)
    assert chosen is not None and {**chosen.describe(), "identity": list(chosen.identity)} == declared["git_selected"]
    cache_calls["warm" if before.get(chosen.path) == chosen else "cold"] += 1
    return chosen

def refused(result):
    global refusals
    held(result)
    assert result["binding_consistent"] is False and result["artifact_observations_complete"] is False
    assert result["snapshot"] is None and result["binding"] is None and result["errors"]
    refusals += 1

def cli(mode, case, expected=None, raw=None, prepared=None, label=None):
    global cli_calls
    argv = [mode, "--root", str(repo)]
    for name in ("baseline", "candidate", "bead-json"):
        argv += ["--" + name, case[name]]
    if mode != "observe":
        argv += ["--review", raw or case["review"], "--expected-context", expected or case["expected"]]
    if mode == "check":
        argv += ["--prepared", prepared or case["prepared"]]
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = binding.main(argv)
    assert stderr.getvalue() == ""
    cli_calls += 1
    result = json.loads(stdout.getvalue())
    held(result)
    note((label or case["name"]) + "/cli/" + mode, "REFUSED" if code else "OBSERVED" if mode == "observe" else "BOUND", result)
    return code, result

def load_case(case):
    values = [document(case[name]) for name in ("baseline", "candidate", "bead-json")]
    raw, expected, saved = Path(case["review"]).read_bytes(), document(case["expected"]), document(case["prepared"])
    assert "sha256:" + hashlib.sha256(raw).hexdigest() == expected["raw_review_sha256"]
    return values, raw, expected, saved

def positive(case, complete):
    values, raw, expected, saved = load_case(case)
    changes = {item["path"]: item for item in values[1]["worktree_manifest"]}
    assert set(changes) == {"src/new.txt", "src/old.txt"}
    assert changes["src/old.txt"]["change"] == "deleted"
    assert changes["src/new.txt"]["change"] == "added"
    assert changes["src/new.txt"]["sha256"] == hashlib.sha256(b"EXAMPLE reliable renamed delivery.\n").hexdigest()
    chain = rb.resolve_chain(values[0])
    assert ci.check_candidate(values[1], root=repo, chain=chain, bead=values[2])["valid"]
    observed = binding.observe(str(repo), *values)
    held(observed)
    assert not observed["errors"] and observed == document(case["observed"])
    note(case["name"] + "/library/observe", "OBSERVED", observed)
    snapshot = observed["snapshot"]
    assert snapshot["root"] == str(repo) and snapshot["candidate"] == values[1]
    assert snapshot["criterion_inventory"] == values[0]["criteria"]
    report = artifacts.prepare(str(repo), *values)
    assert report == snapshot["artifact_report"] and report["candidate_checks"] == {"before": [], "after": []}
    note(case["name"] + "/library/artifacts", "COMPLETE" if complete else "INCOMPLETE", report)
    assert all(report[key] is False for key in ("qualified", "effect_authority",
               "successful_closure_available", "production_accepted", "bead_projection_authenticated"))
    statuses = {entry["id"]: entry["status"] for entry in report["criteria"]}
    assert statuses["EXAMPLE-new-bytes"] == statuses["EXAMPLE-old-absent"] == "PASSED"
    if not complete:
        assert all(statuses[name] == "UNASSESSABLE" for name in (
            "EXAMPLE-validator", "EXAMPLE-review", "EXAMPLE-service"))
    prepared = binding.prepare(str(repo), *values, raw, expected)
    held(prepared)
    assert prepared == saved and prepared["binding_consistent"] is True
    assert prepared["artifact_observations_complete"] is complete
    assert prepared["binding"]["raw_review"].encode("utf-8") == raw
    note(case["name"] + "/library/prepare", "BOUND", prepared)
    consumed = binding.consume(saved, str(repo), *values, raw, expected)
    held(consumed)
    assert consumed == prepared
    note(case["name"] + "/library/check", "BOUND", consumed)
    for mode, wanted in (("observe", observed), ("prepare", prepared), ("check", consumed)):
        code, actual = cli(mode, case)
        assert code == 0 and actual == wanted

def negative_reviews(case):
    values, _, _, saved = load_case(case)
    for variant in declared["negatives"]:
        raw, expected = Path(variant["review"]).read_bytes(), document(variant["expected"])
        prepared = binding.prepare(str(repo), *values, raw, expected)
        consumed = binding.consume(saved, str(repo), *values, raw, expected)
        refused(prepared)
        refused(consumed)
        if variant["name"] == "EXAMPLE-blocker":
            assert prepared["review_verdict"] == "APPROVE"
            assert prepared["unresolved_blocking_finding_ids"] == ["EXAMPLE-blocker"]
        for mode, wanted in (("prepare", prepared), ("check", consumed)):
            note(variant["name"] + "/library/" + mode, "REFUSED", wanted)
            code, actual = cli(mode, case, variant["expected"], variant["review"], label=variant["name"])
            assert code == 1 and actual == wanted
            refused(actual)

def drift(case):
    global editing
    values, raw, expected, saved = load_case(case)
    path = repo / "src/new.txt"
    original = path.read_bytes()
    try:
        editing = True
        path.write_bytes(b"EXAMPLE reliability edit after the recorded review.\n")
        editing = False
        assert ci.verify_candidate(values[1], repo)
        observed = binding.observe(str(repo), *values)
        prepared = binding.prepare(str(repo), *values, raw, expected)
        consumed = binding.consume(saved, str(repo), *values, raw, expected)
        for mode, wanted in (("observe", observed), ("prepare", prepared), ("check", consumed)):
            refused(wanted)
            note("drift/library/" + mode, "REFUSED", wanted)
            code, actual = cli(mode, case, label="drift")
            assert code == 1 and actual == wanted
            refused(actual)
    finally:
        editing = True
        path.write_bytes(original)
        editing = False
    restored = binding.consume(saved, str(repo), *values, raw, expected)
    assert restored == saved
    note("restored/library/check", "BOUND", restored)
    code, actual = cli("check", case, label="restored")
    assert code == 0 and actual == saved

def origins():
    found = []
    for name, module in list(sys.modules.items()):
        selected = name not in initial_modules or name == "cwo_core" or name.startswith("cwo_core.")
        if not selected or not getattr(module, "__file__", None):
            continue
        path = Path(module.__file__).resolve()
        if path.is_relative_to(library) and not {"site-packages", "dist-packages"} & set(path.parts):
            continue
        assert path.is_relative_to(scripts)
        assert Path(module.__spec__.origin).resolve() == path
        assert path.relative_to(root).as_posix() in {item["path"] for item in declared["manifest"]["files"]}
        assert str(path) in reads["installed"]
        if hasattr(module, "__path__"):
            assert [Path(value).resolve() for value in module.__path__] == [path.parent]
            assert [Path(value).resolve() for value in module.__spec__.submodule_search_locations] == [path.parent]
        found.append({"name": name, "path": str(path),
                      "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    assert {"cwo_core", "cwo_core.candidate_identity", "cwo_core.requirement_baseline",
            "cwo_core.workspace_capture", "cwo_core.git_store", "cwo_core.beads",
            "prepare_final_review_binding", "prepare_artifact_acceptance",
            "close_bead_with_summary", "check_installed_skill"} <= {item["name"] for item in found}
    assert "tests" not in sys.modules
    return sorted(found, key=lambda item: item["name"])

def control(name, call):
    before = dict(denied)
    try:
        call()
    except EffectRefused as error:
        assert error.args == (name,)
    else:
        raise AssertionError("EXAMPLE reliability observation missed its positive control")
    finally:
        sys.setprofile(profile)
    before[name] += 1
    assert denied == before

def accepted_controls():
    case = declared["cases"]["supported"]
    values, _, _, _ = load_case(case)
    chain = rb.resolve_chain(values[0])
    with patch.object(wc, "_GIT_CACHE", {}):
        for name in ("cold-capture", "warm-capture"):
            actual = ci.capture_candidate(repo, chain=chain, base_commit=values[1]["base_commit"],
                                          scope_paths=("src",))
            assert actual == values[1]
            positive_counts[name] += 1
    fd = os.open(case["baseline"], os.O_PATH | os.O_CLOEXEC)
    try:
        reader = os.open(f"/proc/self/fd/{fd}", os.O_RDONLY | os.O_CLOEXEC)
        try:
            assert os.read(reader, 1) == Path(case["baseline"]).read_bytes()[:1]
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
    case = declared["cases"]["supported"]
    fd = os.open(case["baseline"], os.O_RDONLY | os.O_CLOEXEC)
    replacement = os.open(case["candidate"], os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.dup2(replacement, fd)
        control("read", lambda: open(f"/proc/self/fd/{fd}", "rb"))
    finally:
        os.close(replacement)
        os.close(fd)
    control("read", lambda: open(f"/proc/self/fd/{fd}", "rb"))

failure, phase, origin_records, controls = None, "imports", [], 0
positive_counts = dict.fromkeys(("cold-capture", "warm-capture", "known-descriptor"), 0)
with contextlib.ExitStack() as stack:
    for target, replacement in (("os.open", open_path), ("os.dup", dup),
                                ("os.close", close), ("os.pipe", pipe),
                                ("subprocess.run", run), ("subprocess.Popen", popen)):
        stack.enter_context(patch(target, replacement))
    try:
        binding = importlib.import_module("prepare_final_review_binding")
        artifacts = importlib.import_module("prepare_artifact_acceptance")
        ci = importlib.import_module("cwo_core.candidate_identity")
        wc = importlib.import_module("cwo_core.workspace_capture")
        assert not wc._GIT_CACHE
        assert list(wc.INERT_GIT_CONFIG) == declared["git_configuration"]
        assert wc._environment() == declared["git_environment"]
        native_selection = wc.trusted_git
        stack.enter_context(patch.object(wc, "_GIT_CACHE", {}))
        stack.enter_context(patch.object(wc, "trusted_git", selection))
        rb = importlib.import_module("cwo_core.requirement_baseline")
        beads = importlib.import_module("cwo_core.beads")
        closure = importlib.import_module("close_bead_with_summary")
        checker = importlib.import_module("check_installed_skill")
        phase = "projection"
        assert checker.REPO_ROOT == root and checker.build_manifest(root) == declared["manifest"]
        record = json.loads((root / ".cwo-install-manifest.json").read_bytes())
        assert record["source_dir"] == str(source) and record["projection"] == declared["manifest"]["projection"]
        assert all(record[name] == declared["manifest"]["content_sha256"]
                   for name in ("source_content_sha256", "installed_content_sha256"))
        assert all(record[name] == declared["manifest"]["file_count"]
                   for name in ("source_file_count", "installed_file_count"))
        assert checker.record_check_status(root)["status"] == "record-consistent"
        phase = "supported-consumer"
        positive(declared["cases"]["supported"], True)
        phase = "unsupported-consumer"
        positive(declared["cases"]["unsupported"], False)
        phase = "review-refusals"
        negative_reviews(declared["cases"]["supported"])
        phase = "private-delivery-drift"
        drift(declared["cases"]["supported"])
        phase = "origins"
        origin_records = origins()
        assert identities(declared["inputs"]) == declared["inputs"]
        assert not any(denied.values()) and git_calls["process-audit"] > 0
        assert cache_calls["cold"] > 0 and cache_calls["warm"] > 0
        assert writes > 2 and mutations > 0 and reads["scratch"]
    except BaseException as error:
        failure = {"phase": phase, "type": type(error).__name__}
    measured, measured_git = dict(denied), dict(git_calls)
    measured_io = {"writes": writes, "mutations": mutations, **capture_io}
    measured_operations = json.loads(json.dumps(operations))
    measured_cache = dict(cache_calls)
    measured_reads = {name: len(paths) for name, paths in reads.items()}
    probes = [
        ("read", lambda: open(checkout / "EXAMPLE_BLOCKED", "rb")),
        ("read", lambda: open(source / "EXAMPLE_BLOCKED", "rb")),
        ("write", lambda: open(root / "EXAMPLE_BLOCKED", "w")),
        ("write", lambda: open(inputs / "EXAMPLE_BLOCKED", "w")),
        ("write", lambda: open(repo / "src/new.txt", "w")),
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
        ("process-run", lambda: subprocess.run(["git", "-C", str(repo), "status"])),
        ("write", lambda: os.open(os.devnull, os.O_RDWR)),
        ("process-audit", lambda: sys.audit("os.posix_spawn", declared["git"], [declared["git"], "--version"], declared["git_environment"])),
        ("process-audit", lambda: sys.audit("_posixsubprocess.fork_exec", [os.fsencode(declared["git"])], [declared["git"], "--version"], [])),
    ]
    listing = [declared["git"], "-C", str(scratch / ("cwo-inspect-" + "0" * 16) / "tree"),
               *declared["git_configuration"], *LISTINGS[0]]
    listing_env = {**declared["git_environment"], "GIT_DIR": str(Path(listing[2]).parent / "git"),
                   "GIT_WORK_TREE": listing[2]}
    listing_options = {"env": listing_env, "stdin": subprocess.DEVNULL,
                       "stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
    probes.extend([
        ("process-Popen", lambda: subprocess.Popen([*listing, "--EXAMPLE-unsupported"], **listing_options)),
        ("process-Popen", lambda: subprocess.Popen(listing, **{**listing_options, "env": {**listing_env, "EXAMPLE_RELIABILITY": "changed"}})),
        ("process-Popen", lambda: subprocess.Popen([listing[0], "-C", str(area / "home"), *listing[3:]], **listing_options)),
    ])
    try:
        accepted_controls()
        descriptor_controls()
        controls += 3
        for name, call in probes:
            control(name, call)
            controls += 1
    except BaseException as error:
        if failure is None:
            failure = {"phase": "positive-controls", "type": type(error).__name__}
sys.setprofile(None)
ok = failure is None and not any(measured.values())
print(json.dumps({
    "ok": ok, "failure": failure, "effects": measured, "git_calls": measured_git,
    "controls": controls, "cli_cases": cli_calls, "refusals": refusals, "origins": origin_records,
    "writes": measured_io["writes"], "mutations": measured_io["mutations"], "reads": measured_reads,
    "capture_io": {name: measured_io[name] for name in capture_io},
    "operations": sorted(measured_operations.values(), key=lambda item: item["operation_sha256"]),
    "cache_calls": measured_cache, "positive_counts": positive_counts,
    "control_effects": {name: denied[name] - measured[name] for name in denied},
    "control_io": {"writes": writes - measured_io["writes"], "mutations": mutations - measured_io["mutations"]},
    "inputs": declared["inputs"], "outcomes": sorted(outcomes.values(), key=lambda item: item["name"]),
    "interpreter": list(sys.version_info[:2]),
    "interpreter_path": sys.executable, "interpreter_version": sys.version,
}, sort_keys=True))
raise SystemExit(0 if ok else 1)
'''


def checked_cleanups(case) -> None:
    if not case.doCleanups():
        raise AssertionError("EXAMPLE nested fixture cleanup failed")


class InstalledFinalReviewConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        seed = cls("test_installed_final_review_lifecycle_without_source")
        cls.addClassCleanup(seed._cleanup_install)
        seed._prepare_install()
        seed.expected = fixture.checker.build_manifest(seed.source)
        seed._assert_resources()
        seed.real_install()
        cls.seed_target = seed.install.target
        cls.seed_record = (cls.seed_target / RECORD).read_bytes()
        cls.seed_snapshot_sha256 = cls.digest(fixture.snapshot(cls.seed_target))
        cls.seed_root_mode = cls.seed_target.lstat().st_mode
        cls.addClassCleanup(cls._verify_seed)
        shutil.rmtree(seed.source)
        seed.assertFalse(seed.source.exists())
        print("CWO_INSTALLED_FINAL_REVIEW_SEED " + json.dumps({
            "schema": "cwo-installed-final-review-seed-v1", "installer_returncode": seed.last_install_returncode,
            "record_sha256": hashlib.sha256(cls.seed_record).hexdigest(),
            "snapshot_sha256": cls.seed_snapshot_sha256, "manifest_sha256": cls.digest(seed.expected),
            "root_mode": cls.seed_root_mode,
        }, sort_keys=True), flush=True)

    @classmethod
    def _verify_seed(cls) -> None:
        if (cls.digest(fixture.snapshot(cls.seed_target)), cls.seed_target.lstat().st_mode) != (
                cls.seed_snapshot_sha256, cls.seed_root_mode):
            raise AssertionError("EXAMPLE installed final-review seed changed")

    def _prepare_install(self) -> None:
        self.install = fixture.InstallerProjectionTests(
            "test_fresh_install_is_the_projection_and_its_resources_are_usable"
        )
        self.addCleanup(self._cleanup_install)
        self.install.setUp()
        self.assertFalse(self.install.tmp.resolve().is_relative_to(fixture.ROOT.resolve()))
        self.source = self.install.copy_source()
        self.inputs, self.scratch = self.install.tmp / "inputs", self.install.tmp / "scratch"
        self.inputs.mkdir()
        self.scratch.mkdir()
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        for key in ("CODEX_HOME", "CODEX_SKILLS_DIR", "PYTHONPATH", "PYTHONHOME",
                    "PYTHONSTARTUP", "BASH_ENV", "ENV"):
            self.env.pop(key, None)
        self.env.update(HOME=str(self.install.tmp / "home"), TMPDIR=str(self.scratch),
                        PYTHONDONTWRITEBYTECODE="1", SKILL_VALIDATOR=str(self.install.tmp / "EXAMPLE_no_validator.py"))

    def setUp(self) -> None:
        self._prepare_install()
        self.delivery = delivery_fixture.ArtifactPreparationTests(
            "test_real_rename_has_complete_but_non_authoritative_bound_observations"
        )
        self.addCleanup(checked_cleanups, self.delivery)
        self.delivery.setUp()
        self._prepare_inputs()
        self.expected = fixture.checker.build_manifest(self.source)
        self._assert_resources()
        self._copy_seed_install()
        prepare_replacement(self)

    def _copy_seed_install(self) -> None:
        before = fixture.snapshot(self.seed_target)
        self.assertEqual((self.digest(before), self.seed_target.lstat().st_mode),
                         (self.seed_snapshot_sha256, self.seed_root_mode))
        shutil.copytree(self.seed_target, self.install.target)
        self.assertEqual(fixture.snapshot(self.install.target), before)
        self.assertEqual(self.install.target.lstat().st_mode, self.seed_root_mode)
        for relative in before:
            self.assertFalse(os.path.samefile(self.seed_target / relative, self.install.target / relative))
        path = self.install.target / RECORD
        self.assertEqual(path.read_bytes(), self.seed_record)
        record = json.loads(self.seed_record)
        self.assertFalse(Path(record["source_dir"]).exists())
        # Rebind only the private source coordinate; retain the real seed receipt separately.
        record["source_dir"] = str(self.source)
        path.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
        self.assertEqual(json.loads(path.read_bytes()), record)
        self.assert_image(self.install.target, self.expected)
        self.initial_image = {"kind": "private-seed-copy", "installer_returncode": None,
                              "root_mode": self.install.target.lstat().st_mode,
                              "seed_record_sha256": hashlib.sha256(self.seed_record).hexdigest(),
                              "private_record_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def _cleanup_install(self) -> None:
        temporary = getattr(self.install, "_tmp", None)
        try:
            checked_cleanups(self.install)
        finally:
            if temporary is not None:
                temporary.cleanup()

    def write_json(self, name: str, value: dict) -> str:
        path = self.inputs / (name + ".json")
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
        return str(path)

    def _records(self) -> dict:
        supported = delivery_fixture.baseline()
        supported["bead_id"] = "EXAMPLE-final-review"
        supported["criteria"] = [
            delivery_fixture.criterion("EXAMPLE-new-bytes", {
                "op": "regular-file-sha256", "path": "src/new.txt", "sha256": hashlib.sha256(NEW).hexdigest()}),
            delivery_fixture.criterion("EXAMPLE-old-absent", {"op": "path-absent", "path": "src/old.txt"}),
        ]
        unsupported = copy.deepcopy(supported)
        unsupported["criteria"] += [
            delivery_fixture.criterion("EXAMPLE-validator", "EXAMPLE reliability validator remains unavailable", "validator"),
            delivery_fixture.criterion("EXAMPLE-review", "EXAMPLE reliability review remains unavailable", "review-gate"),
            delivery_fixture.criterion("EXAMPLE-service", {"op": "service-inactive", "path": "src/new.txt"}),
        ]
        return {"supported": supported, "unsupported": unsupported}

    def _capture_contract(self) -> None:
        self.git_commands = set()
        self.git_executables, self.expected_outcomes = {}, {}
        self.git_environment = capture_fixture._environment()
        self.git_configuration = list(capture_fixture.INERT_GIT_CONFIG)
        self.fixed_git_paths = {os.path.realpath(path) for path in capture_fixture.TRUSTED_GIT_PATHS}

    def _capture_selection(self, native, counts, *args, **kwargs):
        before = dict(capture_fixture._GIT_CACHE)
        chosen = native(*args, **kwargs)
        self.assertIsNotNone(chosen, "EXAMPLE reliability source selection was unavailable")
        selected = {**chosen.describe(), "identity": list(chosen.identity)}
        self.assertEqual(selected, getattr(self, "git_selected", selected))
        self.git_selected, self.git = selected, chosen.path
        counts["warm" if before.get(chosen.path) == chosen else "cold"] += 1
        return chosen

    def _capture_process(self, command, options) -> None:
        executable = os.fsdecode(command[0])
        identity = executable_identity(executable)
        self.assertEqual(identity, self.git_executables.setdefault(executable, identity))
        if list(command)[1:] != ["--version"]:
            self.assertEqual(executable, self.git)
        key = git_key(
            command, options.get("cwd"), options.get("env"), self.scratch, self.fixed_git_paths,
            self.git_configuration, self.git_environment)
        self.git_commands.add(key)

    def _prepare_inputs(self) -> None:
        rb, ci = delivery_fixture.rb, delivery_fixture.ci
        records, projections, self.cases = self._records(), {}, {}
        for name, initial in records.items():
            chain = rb.resolve_chain(initial)
            projections[name] = {"id": chain["bead_id"], "comments": [
                {"text": rb.reference_line(chain["bead_id"], item["version"], item["digest"])}
                for item in chain["baselines"]]}
            self.cases[name] = {
                "name": name,
                "baseline": self.write_json("EXAMPLE-" + name + "-baseline", initial),
                "bead-json": self.write_json("EXAMPLE-" + name + "-bead", projections[name]),
            }
        self._capture_contract()
        cache_calls = dict.fromkeys(("cold", "warm"), 0)
        native_popen = subprocess.Popen
        native_selection = capture_fixture.trusted_git

        def capture_selection(*args, **kwargs):
            return self._capture_selection(native_selection, cache_calls, *args, **kwargs)

        def capture_process(*args, **kwargs):
            command = args[0] if args else kwargs.get("args")
            self._capture_process(command, kwargs)
            return native_popen(*args, **kwargs)

        with patch.dict(os.environ, self.env, clear=True), patch.object(tempfile, "tempdir", str(self.scratch)), \
                patch.object(capture_fixture, "_GIT_CACHE", {}), \
                patch.object(capture_fixture, "trusted_git", side_effect=capture_selection), \
                patch("subprocess.Popen", side_effect=capture_process), delivery_fixture.no_effects():
            self.delivery.begin(records["supported"], change=lambda: (self.delivery.repo / "src/new.txt").write_bytes(NEW))
            for name, initial in records.items():
                chain = rb.resolve_chain(initial)
                candidate = ci.capture_candidate(self.delivery.repo, chain=chain,
                                                 base_commit=self.delivery.base, scope_paths=("src",))
                projection = copy.deepcopy(projections[name])
                projection["comments"].append({"text": ci.candidate_reference_line(
                    chain["bead_id"], ci.candidate_digest(candidate))})
                self.cases[name]["candidate"] = self.write_json("EXAMPLE-" + name + "-candidate", candidate)
                self.cases[name]["bead-json"] = self.write_json("EXAMPLE-" + name + "-bead", projection)
                self._record_review(name, initial, candidate, projection)
            self._negative_inputs()
            self._expected_refusals()
            self._expected_drift()
        self.assertGreater(cache_calls["cold"], 0)
        self.assertGreater(cache_calls["warm"], 0)
        version = git_key(
            [self.git, "--version"], None, self.git_environment, self.scratch, self.fixed_git_paths,
            self.git_configuration, self.git_environment)
        self.assertIn(version, self.git_commands)
        self.capture_context = {
            "git_selected": self.git_selected, "git_executables": self.git_executables,
            "git_configuration": self.git_configuration, "git_environment": self.git_environment,
        }

    def _record_review(self, name: str, initial: dict, candidate: dict, projection: dict) -> None:
        binding = review_fixture.binding
        case = self.cases[name]
        observed = binding.observe(str(self.delivery.repo), initial, candidate, projection)
        self.assertTrue(not observed["errors"], "EXAMPLE source reliability observation was refused")
        case["observed"] = self.write_json("EXAMPLE-" + name + "-observed", observed)
        context = {"review_id": "EXAMPLE-reliability-review", "reviewer": "EXAMPLE unauthenticated reliability reviewer",
                   "verdict": "APPROVE", "snapshot": copy.deepcopy(observed["snapshot"])}
        review = {"record_type": "cwo-experimental-final-review", "version": 1, "context": copy.deepcopy(context),
                  "findings": [], "summary": "EXAMPLE reliability fixture review; authenticity remains unproved."}
        raw = json.dumps(review, ensure_ascii=False).encode("utf-8")
        path = self.inputs / ("EXAMPLE-" + name + "-review.json")
        path.write_bytes(raw)
        case["review"] = str(path)
        expected = {"record_type": "cwo-experimental-final-review-expectation", "version": 1,
                    "context": context, "raw_review_sha256": "sha256:" + hashlib.sha256(raw).hexdigest()}
        case["expected"] = self.write_json("EXAMPLE-" + name + "-expected", expected)
        independently_read = binding.artifacts._document(str(path))
        prepared = binding.prepare(str(self.delivery.repo), initial, candidate, projection, independently_read, expected)
        self.assertTrue(prepared["binding_consistent"], "EXAMPLE source reliability preparation was refused")
        case["prepared"] = self.write_json("EXAMPLE-" + name + "-prepared", prepared)
        self._expect(name, "observe", observed, "OBSERVED")
        self._expect(name, "artifacts", observed["snapshot"]["artifact_report"],
                     "COMPLETE" if name == "supported" else "INCOMPLETE")
        self._expect(name, "prepare", prepared, "BOUND")
        consumed = binding.consume(prepared, str(self.delivery.repo), initial, candidate, projection, independently_read, expected)
        self.assertEqual(consumed, prepared)
        self._expect(name, "check", consumed, "BOUND")

    @staticmethod
    def digest(value: object) -> str:
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        return hashlib.sha256(data).hexdigest()

    def _expect(self, label: str, mode: str, result: dict, status: str) -> None:
        kinds = ("library",) if mode == "artifacts" else ("library", "cli")
        for kind in kinds:
            name = label + "/" + kind + "/" + mode
            self.assertNotIn(name, self.expected_outcomes)
            self.expected_outcomes[name] = {"name": name, "status": status, "result_sha256": self.digest(result)}

    def _source_values(self) -> tuple:
        case = self.cases["supported"]
        values = [json.loads(Path(case[name]).read_bytes()) for name in ("baseline", "candidate", "bead-json")]
        return case, values, json.loads(Path(case["prepared"]).read_bytes())

    def _expected_refusals(self) -> None:
        binding = review_fixture.binding
        _, values, saved = self._source_values()
        for variant in self.negatives:
            raw = Path(variant["review"]).read_bytes()
            expected = json.loads(Path(variant["expected"]).read_bytes())
            prepared = binding.prepare(str(self.delivery.repo), *values, raw, expected)
            consumed = binding.consume(saved, str(self.delivery.repo), *values, raw, expected)
            for mode, result in (("prepare", prepared), ("check", consumed)):
                self.assertIs(result["binding_consistent"], False)
                self._expect(variant["name"], mode, result, "REFUSED")

    def _expected_drift(self) -> None:
        binding = review_fixture.binding
        case, values, saved = self._source_values()
        raw, expected = Path(case["review"]).read_bytes(), json.loads(Path(case["expected"]).read_bytes())
        path, before = self.delivery.repo / "src/new.txt", fixture.snapshot(self.delivery.tmp)
        original = path.read_bytes()
        try:
            path.write_bytes(b"EXAMPLE reliability edit after the recorded review.\n")
            results = (binding.observe(str(self.delivery.repo), *values),
                       binding.prepare(str(self.delivery.repo), *values, raw, expected),
                       binding.consume(saved, str(self.delivery.repo), *values, raw, expected))
            for mode, result in zip(("observe", "prepare", "check"), results):
                self.assertIs(result["binding_consistent"], False)
                self._expect("drift", mode, result, "REFUSED")
        finally:
            path.write_bytes(original)
        self.assertEqual(fixture.snapshot(self.delivery.tmp), before)
        restored = binding.consume(saved, str(self.delivery.repo), *values, raw, expected)
        self.assertEqual(restored, saved)
        self._expect("restored", "check", restored, "BOUND")

    def _negative_inputs(self) -> None:
        case = self.cases["supported"]
        raw = Path(case["review"]).read_bytes()
        expected = json.loads(Path(case["expected"]).read_bytes())
        self.negatives = []
        for name in ("EXAMPLE-hash", "EXAMPLE-context", "EXAMPLE-bytes", "EXAMPLE-blocker"):
            altered, expectation = json.loads(raw), copy.deepcopy(expected)
            if name == "EXAMPLE-hash":
                expectation["raw_review_sha256"] = "sha256:" + hashlib.sha256(b"EXAMPLE wrong reliability bytes").hexdigest()
            elif name == "EXAMPLE-context":
                altered["context"]["reviewer"] = "EXAMPLE different reliability reviewer"
            elif name == "EXAMPLE-blocker":
                altered["findings"] = [{"id": "EXAMPLE-blocker", "blocking": True, "state": "OPEN",
                                        "text": "EXAMPLE unresolved reliability finding"}]
            data = raw + b"\n" if name == "EXAMPLE-bytes" else json.dumps(altered, ensure_ascii=False).encode("utf-8")
            if name in ("EXAMPLE-context", "EXAMPLE-blocker"):
                expectation["raw_review_sha256"] = "sha256:" + hashlib.sha256(data).hexdigest()
            path = self.inputs / (name + "-review.json")
            path.write_bytes(data)
            self.negatives.append({"name": name, "review": str(path),
                                   "expected": self.write_json(name + "-expected", expectation)})

    def _assert_resources(self) -> None:
        paths = {item["path"] for item in self.expected["files"]}
        required = {"SECURITY.md", "policy/install-projection.yaml", "scripts/prepare_final_review_binding.py",
                    "scripts/prepare_artifact_acceptance.py", "scripts/close_bead_with_summary.py",
                    "scripts/check_installed_skill.py", "scripts/cwo_core/__init__.py",
                    "scripts/cwo_core/candidate_identity.py", "scripts/cwo_core/requirement_baseline.py",
                    "scripts/cwo_core/workspace_capture.py", "scripts/cwo_core/git_store.py",
                    "scripts/cwo_core/beads.py", "scripts/cwo_core/util.py"}
        self.assertTrue(required <= paths, "EXAMPLE reliability dependency projection is incomplete")
        self.assertTrue({entry["path"]: entry["kind"] for entry in self.expected["entries"]} == fixture.REQUIRED)

    def assert_image(self, target: Path, expected: dict) -> None:
        self.assertTrue(fixture.checker.build_manifest(target) == expected,
                        "EXAMPLE complete reliability projection differs")
        record = json.loads((target / RECORD).read_bytes())
        self.assertEqual((record["version"], record["status"]), (2, "current"))
        self.assertEqual(record["source_dir"], str(self.source.resolve()))
        self.assertTrue(record["projection"] == expected["projection"], "EXAMPLE reliability projection identity differs")
        for name in ("source_content_sha256", "installed_content_sha256"):
            self.assertEqual(record[name], expected["content_sha256"])
        for name in ("source_file_count", "installed_file_count"):
            self.assertEqual(record[name], expected["file_count"])
        self.assertFalse((target / "tests").exists())

    def run_install(self, **extra_env: str) -> subprocess.CompletedProcess[str]:
        return parent_call("install", self.install.run_installer, source=self.source,
                           extra_env={**self.env, **extra_env})

    def run_check(self, *args: str, source: Path | None = None, phase: str = "installed-check") -> subprocess.CompletedProcess[str]:
        return parent_call(phase, self.install.run_checker, *args,
                           source=self.source if source is None else source)

    def real_install(self) -> None:
        result = self.run_install()
        self.last_install_returncode = result.returncode
        self.assertEqual(result.returncode, 0, process_metadata("install", result))
        self.assert_image(self.install.target, self.expected)
        check = self.run_check("--source-dir", str(self.source),
                               "--installed-dir", str(self.install.target), "--check")
        self.assertEqual(check.returncode, 0, process_metadata("installed-check", check))

    def consume_without_source(self, scenario: str = "fresh", rows=None) -> None:
        self.assertEqual(self.source, self.install.tmp / "source")
        self.assertNotEqual(self.source.resolve(), fixture.ROOT.resolve())
        self.source_manifest = (fixture.checker.build_manifest(self.source) if rows is None
                                else rows[0]["metadata"]["source_manifest"])
        input_paths = sorted((self.install.tmp / "inputs").glob("*.json"))
        input_paths += sorted(path for path in self.delivery.repo.rglob("*") if path.is_file())
        self.input_identities = [{"path": str(path),
                                 "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in input_paths]
        self.assertLessEqual(len(self.input_identities), 256)
        shutil.rmtree(self.source)
        self.assertFalse(self.source.exists())
        delivery_root = getattr(self.delivery, "tmp", self.delivery.repo)
        before, delivery_before = fixture.snapshot(self.install.tmp), fixture.snapshot(delivery_root)
        self.assertEqual(fixture.snapshot(self.install.tmp / "scratch"), {})
        context = {"manifest": self.expected, "repo": str(self.delivery.repo), "git": self.git,
                   "git_commands": sorted(self.git_commands), "cases": self.cases, "negatives": self.negatives,
                   "inputs": self.input_identities, **getattr(self, "capture_context", {})}
        result = parent_call(
            "installed-consumer", subprocess.run,
            [sys.executable, "-I", "-B", "-S", "-c", PROBE, str(self.install.target),
             str(fixture.ROOT.resolve()), str(self.source), str(self.install.tmp)],
            cwd=self.install.tmp / "home", env=self.env, input=json.dumps(context),
            capture_output=True, text=True, check=False, timeout=180,
        )
        after = fixture.snapshot(self.install.tmp)
        self.assertTrue(before == after, "EXAMPLE installed reliability call changed an unnamed path")
        self.assertTrue(fixture.snapshot(delivery_root) == delivery_before, "EXAMPLE delivery reliability fixture was not restored")
        report = self._consumer_report(result)
        self.assertTrue(all(value == 0 for value in report["effects"].values()), "EXAMPLE reliability effect was observed")
        self.assertEqual((report["controls"], report["cli_cases"], report["refusals"]), (26, 18, 22))
        self.assertGreaterEqual(len(report["origins"]), 10)
        self.assertGreater(report["git_calls"]["process-audit"], 0)
        self._assert_capture_evidence(report)
        self.assertGreater(report["writes"], 2)
        self.assertGreater(report["mutations"], 0)
        for name in ("installed", "input", "delivery", "scratch"):
            self.assertGreater(report["reads"][name], 0)
        for row in rows or [None]:
            self._retain_evidence(scenario if row is None else row["row_id"], report, row)

    def _consumer_report(self, result: subprocess.CompletedProcess[str]) -> dict:
        if len(result.stdout.encode("utf-8")) > 131072:
            self.fail(process_metadata("installed-consumer-report", result))
        try:
            report = json.loads(result.stdout)
        except (ValueError, TypeError):
            self.fail(process_metadata("installed-consumer-report", result))
        failure = report.get("failure") if type(report) is dict else None
        if result.returncode != 0 or type(report) is not dict or report.get("ok") is not True:
            phase = "installed-consumer"
            if type(failure) is dict and failure.get("phase") in (
                "imports", "projection", "supported-consumer", "unsupported-consumer",
                "review-refusals", "private-delivery-drift", "origins", "positive-controls"):
                phase = failure["phase"]
            self.fail(process_metadata(phase, result))
        return report

    def _assert_capture_evidence(self, report: dict) -> None:
        operations = report["operations"]
        expected = {hashlib.sha256(key.encode("utf-8")).hexdigest() for key in self.git_commands}
        self.assertEqual({item["operation_sha256"] for item in operations}, expected)
        self.assertEqual(len(operations), len(expected))
        self.assertLessEqual(len(operations), 8)
        calls, events = 0, 0
        sequences = {"subprocess.Popen", "subprocess.Popen|os.posix_spawn",
                     "subprocess.Popen|_posixsubprocess.fork_exec"}
        for item in operations:
            self.assertIn(item["executable"], self.git_executables)
            self.assertGreater(item["calls"], 0)
            self.assertTrue(set(item["sequences"]) <= sequences)
            self.assertTrue(all(type(count) is int and count > 0 for count in item["sequences"].values()))
            self.assertEqual(sum(item["sequences"].values()), item["calls"])
            calls += item["calls"]
            events += sum(len(sequence.split("|")) * count for sequence, count in item["sequences"].items())
        self.assertEqual(calls, report["git_calls"]["process-Popen"])
        self.assertEqual(events, report["git_calls"]["process-audit"])
        self.assertEqual(report["capture_io"]["null_opens"], calls)
        self.assertEqual(report["capture_io"]["pipe_reads"], calls * 2)
        expected_pairs = sum(
            (2 if sequence.endswith("|os.posix_spawn") else 3) * count
            for item in operations for sequence, count in item["sequences"].items())
        self.assertEqual(report["capture_io"]["pipe_pairs"], expected_pairs)
        self.assertGreater(report["cache_calls"]["cold"], 0)
        self.assertGreater(report["cache_calls"]["warm"], 0)
        self.assertEqual(report["positive_counts"], {"cold-capture": 1, "warm-capture": 1, "known-descriptor": 1})
        expected_controls = dict.fromkeys(report["effects"], 1)
        expected_controls.update(read=5, write=4, mutation=1, **{
            "process-run": 2, "process-Popen": 4, "process-audit": 4})
        self.assertEqual(report["control_effects"], expected_controls)
        self.assertGreater(report["control_io"]["writes"], 0)
        self.assertGreater(report["control_io"]["mutations"], 0)

    def _normalized_origins(self, records: list) -> list:
        self.assertLessEqual(len(records), 128)
        self.assertEqual(len({item["name"] for item in records}), len(records))
        self.assertTrue({"cwo_core", "cwo_core.candidate_identity", "cwo_core.workspace_capture",
                         "cwo_core.requirement_baseline", "cwo_core.git_store", "cwo_core.beads",
                         "prepare_final_review_binding", "prepare_artifact_acceptance", "close_bead_with_summary", "check_installed_skill"} <= {item["name"] for item in records})
        files = {item["path"]: item["sha256"] for item in self.expected["files"]}
        normalized = []
        for item in records:
            path = Path(item["path"])
            self.assertTrue(path.is_absolute() and path.is_relative_to(self.install.target / "scripts"))
            relative = path.relative_to(self.install.target).as_posix()
            self.assertEqual(item["sha256"], files[relative])
            self.assertEqual(item["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            normalized.append({"name": item["name"], "path": str(path), "sha256": item["sha256"]})
        return sorted(normalized, key=lambda item: item["name"])

    def _source_evidence(self, origins: list, source_manifest=None) -> dict:
        source_manifest = self.source_manifest if source_manifest is None else source_manifest
        files = {item["path"]: item["sha256"] for item in source_manifest["files"]}
        names = {Path(item["path"]).relative_to(self.install.target).as_posix() for item in origins}
        names.update(("SECURITY.md", "scripts/install.sh"))
        for item in origins:
            relative = Path(item["path"]).relative_to(self.install.target).as_posix()
            self.assertEqual(files[relative], item["sha256"])
        helpers = [{"path": str(self.source / name), "sha256": files[name]} for name in sorted(names)]
        return {"root": str(self.source),
                "manifest_sha256": self.digest(source_manifest), "helpers": helpers}

    def _lifecycle_metadata(self):
        return {"transition": getattr(self, "transition", self.initial_image),
                "source_manifest": fixture.checker.build_manifest(self.source)}

    def _retain_evidence(self, scenario: str, report: dict, row=None) -> None:
        metadata = ({"transition": getattr(self, "transition", self.initial_image),
                     "source_manifest": self.source_manifest} if row is None else row["metadata"])
        self.assertIn(scenario, ("fresh", "replacement", "activation-rollback", "term-rollback"))
        self.assertEqual(report["inputs"], self.input_identities)
        actual_inputs = [{"path": item["path"],
                          "sha256": hashlib.sha256(Path(item["path"]).read_bytes()).hexdigest()}
                         for item in self.input_identities]
        self.assertEqual(actual_inputs, self.input_identities)
        self.assertTrue(self.input_identities, "EXAMPLE reliability input identities are missing")
        self.assertEqual(report["outcomes"], sorted(self.expected_outcomes.values(), key=lambda item: item["name"]))
        self.assertEqual(len(report["outcomes"]), 38)
        self.assertEqual(report["interpreter"], list(sys.version_info[:2]))
        self.assertEqual(report["interpreter_path"], sys.executable)
        self.assertEqual(report["interpreter_version"], sys.version)
        installed = fixture.checker.build_manifest(self.install.target)
        self.assertTrue(installed == self.expected, "EXAMPLE complete reliability manifest differs")
        origins = self._normalized_origins(report["origins"])
        image = {name: {"path": str(self.install.target / name),
                        "sha256": hashlib.sha256((self.install.target / name).read_bytes()).hexdigest()}
                 for name in (RECORD, "SECURITY.md", "scripts/install.sh")}
        evidence = {
            "schema": "cwo-installed-final-review-consumer-evidence-v1", "scenario": scenario,
            "inputs": self.input_identities, "origins": origins,
            "outcomes": report["outcomes"], "source": self._source_evidence(origins, metadata["source_manifest"]),
            "shared_product_flow_sha256": self.digest(report),
            "installation": image, "interpreter": {"path": report["interpreter_path"], "version": report["interpreter_version"]},
            "manifests": {"expected_sha256": self.digest(self.expected), "installed_sha256": self.digest(installed),
                          "content_sha256": installed["content_sha256"], "file_count": installed["file_count"],
                          "projection_sha256": installed["projection"]["sha256"]},
            "capture": {"selected": self.git_selected, "executables": self.git_executables,
                        "operations": report["operations"], "calls": report["git_calls"],
                        "cache_calls": report["cache_calls"], "io": report["capture_io"]},
            "effects": report["effects"], "writes": report["writes"], "mutations": report["mutations"],
            "reads": report["reads"], "positive_counts": report["positive_counts"],
            "control_effects": report["control_effects"], "control_io": report["control_io"],
            "cli_cases": report["cli_cases"], "refusals": report["refusals"],
            "initial_image": self.initial_image,
            "transition": metadata["transition"],
        }
        data = json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        self.assertLessEqual(len(data.encode("utf-8")), 65536)
        print("CWO_INSTALLED_FINAL_REVIEW_EVIDENCE " + data, flush=True)

    def test_installed_final_review_lifecycle_without_source(self) -> None:
        self.assertEqual(self.install.leftovers(), [])
        other = type(self)(self._testMethodName)
        before = fixture.snapshot(self.install.tmp)
        try:
            other._prepare_install()
            other.expected = fixture.checker.build_manifest(other.source)
            other._copy_seed_install()
            self.assertNotEqual(self.install.tmp, other.install.tmp)
            self.assertEqual(self.expected, other.expected)
            self.assertIsNot(self.initial_image, other.initial_image)
            for root in (other.source, other.install.target):
                marker = root / "SECURITY.md"
                marker.write_bytes(marker.read_bytes() + b"\nEXAMPLE private final-review copy.\n")
                marker.chmod(0o600)
            other.initial_image["EXAMPLE"] = "private"
            self.assertEqual(fixture.snapshot(self.install.tmp), before)
            self._verify_seed()
            try:
                self.seed_target.chmod(stat.S_IMODE(self.seed_root_mode) ^ 0o020)
                with self.assertRaisesRegex(AssertionError, "EXAMPLE installed final-review seed changed"):
                    self._verify_seed()
            finally:
                self.seed_target.chmod(stat.S_IMODE(self.seed_root_mode))
            self._verify_seed()
        finally:
            checked_cleanups(other)
        shared = RestoredInstalledRows(self, self._lifecycle_metadata)
        with patch.object(self, "_defer_source_absent_consumer", True, create=True):
            shared.exercise_rollbacks(("term",))
        shared.retain()
        with self.subTest(rows=("fresh", "term-rollback")):
            self.consume_without_source(rows=shared.rows)
        with self.subTest(row="replacement"):
            self.replacement_case.replacement_row()

    def replacement_row(self) -> None:
        (self.install.target / "SECURITY.md").unlink()
        (self.install.target / RECORD).write_text(json.dumps(fixture.V1_RECORD), encoding="utf-8")
        status = fixture.checker.installed_status(self.source, self.install.target)
        self.assertEqual(status["status"], "drift")
        self.assertEqual(status["missing_files"], ["SECURITY.md"])
        self.assertEqual(status["previous_install_record"]["version"], 1)
        previous = fixture.snapshot(self.install.target)
        self.real_install()
        backups = list(self.install.backups.glob(f"{fixture.SKILL}.prev.*"))
        self.assertEqual(len(backups), 1)
        self.assertTrue(fixture.snapshot(backups[0]) == previous, "EXAMPLE reliability replacement backup differs")
        self.assertEqual(list(self.install.skills.glob(f".{fixture.SKILL}.stage.*")), [])
        self.transition = {"installer_returncode": self.last_install_returncode,
                           "previous_sha256": self.digest(previous),
                           "backup_sha256": self.digest(fixture.snapshot(backups[0]))}
        self.consume_without_source("replacement")

    def rollback(self, mode: str) -> None:
        previous, source_before = fixture.snapshot(self.install.target), fixture.snapshot(self.source)
        security = self.source / "SECURITY.md"
        security.write_bytes(security.read_bytes() + b"\nEXAMPLE disposable reliability rollback stage.\n")
        source_after = fixture.snapshot(self.source)
        self.assertEqual(set(source_before), set(source_after))
        self.assertEqual({path for path in source_before if source_before[path] != source_after[path]}, {"SECURITY.md"})
        replacement = fixture.checker.build_manifest(self.source)
        self.assertNotEqual(replacement["content_sha256"], self.expected["content_sha256"])
        self.assertEqual(fixture.checker.compare_manifests(self.expected, replacement)["changed_files"], ["SECURITY.md"])
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
            self.assertEqual(result.returncode, 143, process_metadata("install-term", result))
        else:
            self.assertNotEqual(result.returncode, 0, process_metadata("install-activation", result))
            self.assertIn(f"error: could not activate staged install at {self.install.target}", result.stderr.splitlines())
        self.assertIn(f"Restored the previous install at {self.install.target}", result.stderr.splitlines())
        self.assertTrue(fixture.snapshot(self.install.target) == previous, "EXAMPLE reliability rollback differs")
        self.assertTrue(fixture.snapshot(self.source) == source_after, "EXAMPLE reliability source changed")
        self.assertEqual(self.install.leftovers(), [])
        stage, backup = (Path(line) for line in event.read_text(encoding="utf-8").splitlines())
        self.assertEqual(stage.parent, self.install.skills)
        self.assertTrue(stage.name.startswith(f".{fixture.SKILL}.stage."))
        self.assertEqual(backup.parent, self.install.backups)
        self.assertTrue(backup.name.startswith(f"{fixture.SKILL}.prev."))
        self.assert_image(witness, replacement)
        self.assert_image(self.install.target, self.expected)
        check = self.run_check("--source-dir", str(self.install.target),
                               "--installed-dir", str(self.install.target), "--check",
                               source=self.install.target, phase="restored-check")
        self.assertEqual(check.returncode, 0, process_metadata("restored-check", check))
        self.transition = {"installer_returncode": result.returncode, "mode": mode,
                           "stderr_sha256": hashlib.sha256(result.stderr.encode("utf-8")).hexdigest(),
                           "previous_sha256": self.digest(previous),
                           "restored_sha256": self.digest(fixture.snapshot(self.install.target)),
                           "source_before_sha256": self.digest(source_before), "source_after_sha256": self.digest(source_after),
                           "stage": str(stage), "backup": str(backup),
                           "witness_manifest_sha256": self.digest(fixture.checker.build_manifest(witness))}
        shutil.rmtree(witness)
        if not getattr(self, "_defer_source_absent_consumer", False):
            self.consume_without_source(mode + "-rollback")


    def test_activation_rollback_installed_final_review_without_source(self) -> None:
        self.rollback("activation")


class ParentTimeoutDiagnosticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.install = fixture.InstallerProjectionTests(
            "test_fresh_install_is_the_projection_and_its_resources_are_usable"
        )
        self.addCleanup(InstalledFinalReviewConsumerTests._cleanup_install, self)
        self.install.setUp()
        self.case = InstalledFinalReviewConsumerTests(
            "test_installed_final_review_lifecycle_without_source"
        )
        self.case.install = self.install
        self.case.source = self.install.copy_source()
        self.case.env = {**os.environ, "HOME": str(self.install.tmp / "home"),
                         "SKILL_VALIDATOR": str(self.install.tmp / "EXAMPLE_NO_VALIDATOR.py"),
                         "PYTHONDONTWRITEBYTECODE": "1"}
        for key in ("CODEX_HOME", "CODEX_SKILLS_DIR", "PYTHONPATH", "PYTHONHOME",
                    "PYTHONSTARTUP", "BASH_ENV", "ENV"):
            self.case.env.pop(key, None)
        self.case.expected = fixture.checker.build_manifest(self.case.source)
        self.case.delivery = SimpleNamespace(repo=self.install.tmp / "EXAMPLE-delivery")
        self.case.delivery.repo.mkdir()
        self.case.git = "/EXAMPLE_GIT"
        self.case.git_commands = set()
        self.case.cases, self.case.negatives = {}, []

    def test_parent_timeouts_have_bounded_failure_records(self) -> None:
        calls = (
            ("install", self.case.run_install),
            ("installed-check", lambda: self.case.run_check("--check")),
            ("restored-check", lambda: self.case.run_check("--check",
                                                         source=self.install.target, phase="restored-check")),
            ("installed-consumer", self.case.consume_without_source),
        )
        for phase, call in calls:
            with self.subTest(phase=phase):
                stdout = io.StringIO()
                timeout = subprocess.TimeoutExpired(
                    ["EXAMPLE_COMMAND_TEXT_MUST_NOT_APPEAR"], 1,
                    output=b"EXAMPLE_CAPTURED_CONTENT", stderr=b"EXAMPLE_CAPTURED_CONTENT")
                with contextlib.redirect_stdout(stdout), patch.object(
                        subprocess, "run", side_effect=timeout):
                    with self.assertRaises(AssertionError) as caught:
                        call()
                rendered = "".join(traceback.format_exception(caught.exception))
                self.assertNotIn("EXAMPLE_COMMAND_TEXT_MUST_NOT_APPEAR", rendered)
                self.assertNotIn("EXAMPLE_CAPTURED_CONTENT", rendered)
                self.assertNotIn(PROBE, rendered)
                self.assertNotIn("CWO_INSTALLED_FINAL_REVIEW_EVIDENCE ", stdout.getvalue())
                self.assertEqual(json.loads(str(caught.exception)),
                                 {"phase": phase, "status": "failed", "type": "TimeoutExpired"})
                self.assertLess(len(rendered), 4000)

    def test_parent_boundary_preserves_nonzero_and_unrelated_errors(self) -> None:
        completed = subprocess.CompletedProcess(["EXAMPLE_NEVER_RUN"], 23, "", "")
        with patch.object(subprocess, "run", return_value=completed):
            self.assertIs(self.case.run_install(), completed)
        error = RuntimeError("EXAMPLE unrelated reliability failure")
        with patch.object(subprocess, "run", side_effect=error):
            with self.assertRaises(RuntimeError) as caught:
                self.case.run_install()
        self.assertIs(caught.exception, error)
        for cleanup in (checked_cleanups, lambda case: self.case._cleanup_install()):
            with self.subTest(cleanup="nested fixture failure"):
                failed = unittest.TestCase()
                failed.addCleanup(self.fail, "EXAMPLE injected nested cleanup failure")
                with patch.object(self.case, "install", failed), self.assertRaisesRegex(
                        AssertionError, "EXAMPLE nested fixture cleanup failed"):
                    cleanup(failed)



if __name__ == "__main__":
    unittest.main()
