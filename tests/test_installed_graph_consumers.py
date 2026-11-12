"""Regression evidence for installed graph consumers in disposable images."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

from tests.installed_consumer_fixtures import RestoredInstalledRows, prepare_replacement
from tests import test_install_projection as fixture
from tests.test_installed_numeric_rollback import MV_SHIM


RECORD = ".cwo-install-manifest.json"


PROBE = r'''
import contextlib
import copy
import importlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from unittest.mock import patch

root, checkout, source, area = (Path(value).resolve() for value in sys.argv[1:5])
expected = json.load(sys.stdin)
scripts, output = root / "scripts", area / "outputs/EXAMPLE_graph.md"
library = Path(os.__file__).resolve().parent
assert sys.flags.isolated and sys.dont_write_bytecode
assert root == area / "skills/complex-work-orchestration"
assert source == area / "source" and not source.exists()
assert not area.is_relative_to(checkout)
assert Path.cwd() == area / "home" == Path(os.environ["HOME"]).resolve()
assert all(not Path(item).resolve().is_relative_to(checkout) for item in sys.path)
assert all(not Path(item).resolve().is_relative_to(source) for item in sys.path)
assert "scaffold_workgraph" not in sys.modules
assert not any(name == "cwo_core" or name.startswith("cwo_core.") for name in sys.modules)
sys.path.insert(0, str(scripts))
reads = {"installed": set(), "library": set(), "output": set()}
effects = dict.fromkeys((
    "read", "write", "mutation", "process-run", "process-Popen", "process-audit",
    "socket", "temporary-directory", "temporary-file",
    "beads-create", "beads-link", "beads-run", "beads-structured",
), 0)
descriptors, opening, writes = {}, [], 0
real_open = os.open

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

def observe_path(path, flags):
    global writes
    if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
        if path != output:
            block("write")
        writes += 1
        return
    if path.is_relative_to(root):
        label = "installed"
    elif path == output:
        label = "output"
    elif path.is_relative_to(library) and not {"site-packages", "dist-packages"} & set(path.parts):
        label = "library"
    else:
        block("read")
    reads[label].add(str(path))

def audit(event, args):
    if event == "open":
        path = opening[-1] if opening else path_for(args[0])
        observe_path(path, args[2] or 0)
    elif event in {"os.listdir", "os.scandir"}:
        observe_path(path_for(args[0]), 0)
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

def guard(name):
    return lambda *args, **kwargs: block(name)

# Observe reliability effects before any installed import.
sys.addaudithook(audit)

def item(lane):
    return {
        "title": "EXAMPLE reliable " + lane, "type": "task", "lane": lane,
        "labels": ["EXAMPLE_RELIABILITY"], "skills": ["EXAMPLE_VALIDATION"],
        "depends_on_lanes": [], "acceptance": "EXAMPLE reliable result.",
        "design": "EXAMPLE bounded reliability check.", "notes": "EXAMPLE review remains required.",
        "metadata": {"EXAMPLE_FLAG": True, "EXAMPLE_EMPTY": None, "EXAMPLE_LIST": ["EXAMPLE_VALUE"]},
    }

def plan():
    epic = item("EXAMPLE_EPIC")
    del epic["lane"]
    epic["type"] = "epic"
    epic["depends_on_lanes"] = [{"key": " architect ", "dependency_type": "VALIDATES"}]
    first, last = item("architect"), item("EXAMPLE_LAST")
    first["depends_on_lanes"] = [
        " EXAMPLE_LAST ", {"key": "EXAMPLE_LAST", "dependency_type": "RELATES_TO"},
        {"lane": "EXAMPLE_LAST", "type": "UNTIL"},
    ]
    last["depends_on_lanes"] = [{"lane": "architect", "type": "tracks"}]
    return [epic, first, last]

def invoke(graph, options, supplied=None):
    out, err = io.StringIO(), io.StringIO()
    failure = None
    title = "EXAMPLE_GRAPH" if supplied is not None else "EXAMPLE reliability maintenance"
    with contextlib.ExitStack() as stack:
        if supplied is not None:
            producer = stack.enter_context(patch.object(graph, "planned_graph", return_value=supplied))
        stack.enter_context(patch.object(sys, "argv", [
            "scaffold_workgraph.py", "--title", title,
            "--description", "Explain a small local project maintenance change.", *options,
        ]))
        stack.enter_context(contextlib.redirect_stdout(out))
        stack.enter_context(contextlib.redirect_stderr(err))
        try:
            graph.main()
        except SystemExit as error:
            failure = error
        if supplied is not None:
            assert producer.call_count == 1
    assert err.getvalue() == ""
    assert not any(effects.values())
    return failure, out.getvalue()

def exercise(graph):
    count, refused = 0, 0
    failure, text = invoke(graph, ("--dry-run",))
    count += 1
    assert failure is None and text.endswith("\n")
    genuine = json.loads(text)
    assert len(genuine) >= 8 and genuine[0]["type"] == "epic"
    assert {"architect", "pm", "implementation", "docs", "validation"} <= {
        entry.get("lane") for entry in genuine
    }
    assert graph.beads_graph_plan(genuine)["nodes"]
    assert graph.WORKGRAPH_FALLBACK_MARKER in graph.markdown_workgraph_plan("EXAMPLE_GRAPH", genuine)
    value = plan()
    before = copy.deepcopy(value)
    exported = graph.beads_graph_plan(value)
    nodes = exported["nodes"]
    assert [node["key"] for node in nodes] == ["epic", "architect", "EXAMPLE_LAST"]
    assert [node["priority"] for node in nodes] == [1, 1, 2]
    assert [node["title"] for node in nodes] == [entry["title"] for entry in value]
    assert "parent_key" not in nodes[0]
    assert all(node["parent_key"] == "epic" for node in nodes[1:])
    for entry, node in zip(value, nodes):
        metadata = node["metadata"]
        assert node["type"] == entry["type"] and node["labels"] == entry["labels"]
        assert all(isinstance(field, str) for field in metadata.values())
        assert json.loads(metadata["cwo_skills"]) == entry["skills"]
        assert json.loads(metadata["cwo_depends_on_lanes"]) == entry["depends_on_lanes"]
        assert metadata["cwo_lane"] == entry.get("lane", "epic")
        for field in ("acceptance", "design", "notes"):
            assert metadata["cwo_" + field] == entry[field]
        assert metadata["cwo_metadata_EXAMPLE_FLAG"] == "True"
        assert metadata["cwo_metadata_EXAMPLE_EMPTY"] == ""
        assert json.loads(metadata["cwo_metadata_EXAMPLE_LIST"]) == ["EXAMPLE_VALUE"]
    assert [(edge["from_key"], edge["to_key"], edge["type"]) for edge in exported["edges"]] == [
        ("epic", "architect", "validates"), ("architect", "EXAMPLE_LAST", "blocks"),
        ("architect", "EXAMPLE_LAST", "relates-to"), ("architect", "EXAMPLE_LAST", "until"),
        ("EXAMPLE_LAST", "architect", "tracks"),
    ]
    markdown = graph.markdown_workgraph_plan("EXAMPLE_GRAPH", value)
    assert graph.WORKGRAPH_FALLBACK_MARKER in markdown
    assert [line for line in markdown.splitlines() if line.startswith("### ")] == [
        "### epic: EXAMPLE reliable EXAMPLE_EPIC", "### architect: EXAMPLE reliable architect",
        "### EXAMPLE_LAST: EXAMPLE reliable EXAMPLE_LAST",
    ]
    for mode, expected_value in (("cwo", value), ("beads-graph", exported), ("markdown-workgraph", markdown)):
        failure, text = invoke(graph, ("--dry-run", "--format", mode), value)
        count += 1
        assert failure is None
        assert text == (expected_value if mode == "markdown-workgraph" else
                        json.dumps(expected_value, indent=2, sort_keys=True) + "\n")
    assert value == before
    output.write_text(markdown, encoding="utf-8")
    assert output.read_text(encoding="utf-8") == markdown
    for title in (7, 0, None, False, {}, []):
        assert graph.beads_graph_plan([{"title": title}])["nodes"][0]["title"] == str(title)
        assert f"### epic: {title or 'epic'}\n" in graph.markdown_workgraph_plan("EXAMPLE_GRAPH", [{"title": title}])
    assert "### epic: epic\n" in graph.markdown_workgraph_plan("EXAMPLE_GRAPH", [{}])
    try:
        graph.beads_graph_plan([{}])
    except ValueError as error:
        assert "must have a title" in str(error)
    else:
        raise AssertionError("EXAMPLE missing title reliability refusal was absent")
    invalid = []
    missing = plan()
    missing[1]["depends_on_lanes"] = ["EXAMPLE_MISSING"]
    invalid.append((missing, "missing dependency reference"))
    duplicate = plan()
    duplicate[1].pop("lane")
    duplicate[2]["lane"] = "item-1"
    invalid.append((duplicate, "duplicate node key"))
    cycle = plan()
    cycle[2]["depends_on_lanes"] = [{"lane": "architect", "type": "until"}]
    invalid.append((cycle, "readiness dependency cycle"))
    options = ((), ("--dry-run",), ("--dry-run", "--format", "cwo"),
               ("--dry-run", "--format", "beads-graph"),
               ("--dry-run", "--format", "markdown-workgraph"))
    for bad, message in invalid:
        retained = copy.deepcopy(bad)
        for call in (lambda: graph.beads_graph_plan(bad),
                     lambda: graph.markdown_workgraph_plan("EXAMPLE_GRAPH", bad)):
            try:
                call()
            except ValueError as error:
                assert message in str(error)
                refused += 1
            else:
                raise AssertionError("EXAMPLE invalid graph reliability refusal was absent")
        for flags in options:
            failure, text = invoke(graph, flags, bad)
            count += 1
            assert isinstance(failure, SystemExit) and message in str(failure) and text == ""
            refused += 1
        assert bad == retained
    return count, refused

def bindings():
    found = 0
    for name, module in list(sys.modules.items()):
        if not (name == "cwo_core" or name.startswith("cwo_core.") or
                name in {"scaffold_workgraph", "check_installed_skill"}):
            continue
        relative = "cwo_core/__init__.py" if name == "cwo_core" else name.replace(".", "/") + ".py"
        path = scripts / relative
        assert Path(module.__file__).resolve() == path
        assert Path(module.__spec__.origin).resolve() == path
        if hasattr(module, "__path__"):
            assert [Path(entry).resolve() for entry in module.__path__] == [path.parent]
            assert [Path(entry).resolve() for entry in module.__spec__.submodule_search_locations] == [path.parent]
        assert str(path) in reads["installed"]
        found += 1
    assert {"scaffold_workgraph", "cwo_core", "cwo_core.beads", "check_installed_skill"} <= sys.modules.keys()
    assert "tests" not in sys.modules
    return found

def control(name, call):
    before = dict(effects)
    try:
        call()
    except EffectRefused as error:
        assert error.args == (name,)
    else:
        raise AssertionError("EXAMPLE reliability observer missed its positive control")
    before[name] += 1
    assert effects == before

def diagnostic(error, phase):
    frames, frame = [], error.__traceback__
    while frame is not None and len(frames) < 8:
        frames.append([frame.tb_frame.f_code.co_filename, frame.tb_frame.f_code.co_name, frame.tb_lineno])
        frame = frame.tb_next
    return {"type": type(error).__name__, "phase": phase, "frames": frames}

failure, phase, graph, beads = None, "imports", None, None
cli_count, refusals, origins, controls = 0, 0, 0, 0
with contextlib.ExitStack() as stack:
    for target, name in (
        ("os.open", None), ("subprocess.run", "process-run"), ("subprocess.Popen", "process-Popen"),
        ("tempfile.TemporaryDirectory", "temporary-directory"),
        ("tempfile.NamedTemporaryFile", "temporary-file"),
    ):
        stack.enter_context(patch(target, open_path if name is None else guard(name)))
    try:
        graph = importlib.import_module("scaffold_workgraph")
        beads = importlib.import_module("cwo_core.beads")
        checker = importlib.import_module("check_installed_skill")
        for module, attribute, name in (
            (graph, "create_bead", "beads-create"), (beads, "create_bead", "beads-create"),
            (graph, "add_dependency", "beads-link"), (beads, "add_dependency", "beads-link"),
            (beads, "run_bd", "beads-run"), (beads, "run_bd_structured", "beads-structured"),
        ):
            stack.enter_context(patch.object(module, attribute, side_effect=guard(name)))
        phase = "manifest"
        assert checker.REPO_ROOT == root and checker.build_manifest(root) == expected
        record = json.loads((root / ".cwo-install-manifest.json").read_text(encoding="utf-8"))
        assert record["source_dir"] == str(source) and record["projection"] == expected["projection"]
        for key in ("source_content_sha256", "installed_content_sha256"):
            assert record[key] == expected["content_sha256"]
        for key in ("source_file_count", "installed_file_count"):
            assert record[key] == expected["file_count"]
        phase = "graph-consumers"
        cli_count, refusals = exercise(graph)
        phase = "origins"
        origins = bindings()
        assert not any(effects.values()) and writes > 0 and reads["output"]
    except BaseException as error:
        failure = diagnostic(error, phase)
    measured = dict(effects)
    try:
        phase = "positive-controls"
        probes = [
            ("read", lambda: open(checkout / "EXAMPLE_BLOCKED", "rb")),
            ("read", lambda: open(source / "EXAMPLE_BLOCKED", "rb")),
            ("write", lambda: open(root / "EXAMPLE_BLOCKED", "w")),
            ("write", lambda: open(output.with_name("EXAMPLE_BLOCKED"), "w")),
            ("mutation", lambda: os.mkdir(area / "home/EXAMPLE_BLOCKED")),
            ("process-run", lambda: subprocess.run(["EXAMPLE_NEVER_RUN"])),
            ("process-Popen", lambda: subprocess.Popen(["EXAMPLE_NEVER_RUN"])),
            ("process-audit", lambda: sys.audit("subprocess.Popen", None, None, None, None)),
            ("socket", lambda: socket.socket()),
            ("temporary-directory", lambda: tempfile.TemporaryDirectory()),
            ("temporary-file", lambda: tempfile.NamedTemporaryFile()),
        ]
        if graph is not None and beads is not None:
            probes += [
                ("beads-create", lambda: graph.create_bead("EXAMPLE_NEVER_CREATED")),
                ("beads-link", lambda: graph.add_dependency("EXAMPLE_FIRST", "EXAMPLE_LAST")),
                ("beads-run", lambda: beads.run_bd(["EXAMPLE_NEVER_RUN"])),
                ("beads-structured", lambda: beads.run_bd_structured(
                    ["EXAMPLE_NEVER_RUN"], directory=area, database="EXAMPLE_UNUSED", actor="EXAMPLE_ACTOR")),
            ]
        for name, call in probes:
            control(name, call)
            controls += 1
    except BaseException as error:
        if failure is None:
            failure = diagnostic(error, phase)
ok = failure is None and not any(measured.values())
print(json.dumps({
    "ok": ok, "failure": failure, "effects": measured, "controls": controls,
    "reads": {name: len(paths) for name, paths in reads.items()}, "writes": writes,
    "cli_cases": cli_count, "refusals": refusals, "origins": origins,
    "interpreter": list(sys.version_info[:2]),
}, sort_keys=True))
raise SystemExit(0 if ok else 1)
'''


class InstalledGraphConsumerTests(unittest.TestCase):
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
            "SKILL_VALIDATOR": str(self.install.tmp / "EXAMPLE_no_validator.py"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PATH": str(self.install.shims) + os.pathsep + os.environ.get("PATH", os.defpath),
        }
        for key in (
            "CODEX_HOME", "CODEX_SKILLS_DIR", "PYTHONPATH", "PYTHONHOME",
            "PYTHONSTARTUP", "BASH_ENV", "ENV",
        ):
            self.env.pop(key, None)
        (self.install.tmp / "outputs").mkdir()
        self.expected = fixture.checker.build_manifest(self.source)
        paths = {entry["path"] for entry in self.expected["files"]}
        self.assertTrue({
            "SECURITY.md", "policy/install-projection.yaml", "scripts/scaffold_workgraph.py",
            "scripts/cwo_core/beads.py", "scripts/cwo_core/workgraph_markdown.py",
        } <= paths, "EXAMPLE required reliability resources are missing")
        for prefix in ("policy/", "schemas/", "references/", "scripts/cwo_core/"):
            self.assertTrue(any(path.startswith(prefix) for path in paths), prefix)
        self.real_install()
        prepare_replacement(self)

    def _cleanup_install(self) -> None:
        temporary = getattr(self.install, "_tmp", None)
        try:
            self.install.doCleanups()
        finally:
            if temporary is not None:
                temporary.cleanup()

    def run_install(self, **extra_env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(self.source / "scripts/install.sh"),
             "--skills-dir", str(self.install.skills), "--yes"],
            cwd=self.install.tmp, env={**self.env, **extra_env},
            capture_output=True, text=True, check=False, timeout=180,
        )

    def assert_image(self, target: Path, expected: dict) -> None:
        actual = fixture.checker.build_manifest(target)
        self.assertTrue(actual == expected, "EXAMPLE complete reliability projection differs")
        record = json.loads((target / RECORD).read_text(encoding="utf-8"))
        self.assertEqual((record["version"], record["status"]), (2, "current"))
        self.assertEqual(record["source_dir"], str(self.source.resolve()))
        self.assertTrue(record["projection"] == expected["projection"], "EXAMPLE reliability projection identity differs")
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
        security.write_bytes(security.read_bytes() + b"\nEXAMPLE disposable reliability replacement marker.\n")
        after = fixture.snapshot(self.source)
        self.assertTrue(before.keys() == after.keys(), "EXAMPLE reliability source inventory changed")
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
            [sys.executable, "-I", "-B", "-c", PROBE, str(self.install.target),
             str(fixture.ROOT.resolve()), str(self.source), str(self.install.tmp)],
            cwd=self.install.tmp / "home", env=self.env, input=json.dumps(self.expected),
            capture_output=True, text=True, check=False, timeout=60,
        )
        after = fixture.snapshot(self.install.tmp)
        allowed = "outputs/EXAMPLE_graph.md"
        self.assertTrue(
            {key: value for key, value in before.items() if key != allowed} ==
            {key: value for key, value in after.items() if key != allowed},
            "EXAMPLE installed reliability call changed an unnamed path",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertIs(report["ok"], True)
        self.assertTrue(all(value == 0 for value in report["effects"].values()), "EXAMPLE reliability effects observed")
        self.assertEqual(report["controls"], 15)
        self.assertEqual((report["cli_cases"], report["refusals"]), (19, 21))
        self.assertGreaterEqual(report["origins"], 4)
        self.assertGreater(report["reads"]["installed"], 0)
        self.assertGreater(report["reads"]["output"], 0)
        self.assertGreater(report["writes"], 0)

    def test_installed_graph_lifecycle_without_source(self) -> None:
        self.assertEqual(self.install.leftovers(), [])
        shared = RestoredInstalledRows(self)
        shared.exercise_rollbacks()
        shared.retain()
        with self.subTest(rows=("fresh", "activation-rollback", "term-rollback")):
            self.consume_without_source()
        with self.subTest(row="replacement"):
            self.replacement_case.replacement_row()

    def replacement_row(self) -> None:
        previous = fixture.snapshot(self.install.target)
        self.expected = self.prepare_replacement()
        self.real_install()
        backups = list(self.install.backups.glob(f"{fixture.SKILL}.prev.*"))
        self.assertEqual(len(backups), 1)
        self.assertTrue(fixture.snapshot(backups[0]) == previous, "EXAMPLE reliability backup differs")
        self.assertEqual(list(self.install.skills.glob(f".{fixture.SKILL}.stage.*")), [])
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
        self.assertTrue(fixture.snapshot(self.install.target) == previous, "EXAMPLE reliability rollback differs")
        self.assertTrue(fixture.snapshot(self.source) == source_before, "EXAMPLE reliability source changed")
        self.assertEqual(self.install.leftovers(), [])
        stage, backup = (Path(line) for line in event.read_text(encoding="utf-8").splitlines())
        self.assertEqual(stage.parent, self.install.skills)
        self.assertTrue(stage.name.startswith(f".{fixture.SKILL}.stage."))
        self.assertEqual(backup.parent, self.install.backups)
        self.assertTrue(backup.name.startswith(f"{fixture.SKILL}.prev."))
        self.assert_image(witness, replacement)
        self.assert_image(self.install.target, self.expected)
        shutil.rmtree(witness)


if __name__ == "__main__":
    unittest.main()
