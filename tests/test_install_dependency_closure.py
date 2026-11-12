"""Permanent disposable-install closure and bounded first-run regressions."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from tests import test_install_projection as fixture


# Each consumer starts with -I -B, away from the checkout, with a private HOME.
# This inventory comes from actual source files, not __all__ or a module shortlist.
def module_inventory(root: Path) -> dict[str, str]:
    package = root / "scripts" / "cwo_core"
    result: dict[str, str] = {}
    for path in sorted(package.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        parts = list(path.relative_to(root / "scripts").with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        if not all(part.isidentifier() for part in parts):
            raise AssertionError(f"not an importable module path: {path}")
        name = ".".join(parts)
        if name in result:
            raise AssertionError(f"duplicate module name: {name}")
        result[name] = path.relative_to(root).as_posix()
    if result.get("cwo_core") != "scripts/cwo_core/__init__.py":
        raise AssertionError("source package initializer is missing")
    return result


PREAMBLE = r'''
import contextlib
import hashlib
import importlib
import io
import json
import runpy
import subprocess
import sys
import urllib.request
from pathlib import Path
from unittest.mock import patch

root = Path(sys.argv[1]).resolve()
source = Path(sys.argv[2]).resolve()
expected = json.loads(sys.argv[3])
payload = json.loads(sys.argv[4])
assert root != source and not root.is_relative_to(source)
assert not any(name == "cwo_core" or name.startswith("cwo_core.") for name in sys.modules)
assert str(source / "scripts") not in sys.path
sys.path.insert(0, str(root / "scripts"))

def bindings():
    for name, module in list(sys.modules.items()):
        if name != "cwo_core" and not name.startswith("cwo_core."):
            continue
        assert name in expected, ("unexpected core module", name)
        wanted = (root / expected[name]).resolve()
        assert Path(module.__file__).resolve() == wanted, (name, module.__file__, wanted)
        assert Path(module.__spec__.origin).resolve() == wanted, (name, module.__spec__)
        if wanted.name == "__init__.py":
            assert [Path(p).resolve() for p in module.__path__] == [wanted.parent], name
            assert [Path(p).resolve() for p in module.__spec__.submodule_search_locations] == [wanted.parent], name

def observe(action):
    with patch("subprocess.Popen", side_effect=AssertionError("process guard reached")) as process, \
            patch("urllib.request.urlopen", side_effect=AssertionError("urlopen guard reached")) as network:
        result = action()
        bindings()
        observed = (process.call_count, network.call_count)
        assert observed == (0, 0), observed
        # Controls run strictly AFTER the observation; no real process or URL is used.
        for call, diagnostic in (
            (lambda: subprocess.Popen(["never-start"]), "process guard reached"),
            (lambda: urllib.request.urlopen("https://never-connect.invalid"), "urlopen guard reached"),
        ):
            try:
                call()
            except AssertionError as exc:
                assert str(exc) == diagnostic, str(exc)
            else:
                raise AssertionError("guard control did not refuse")
        assert (process.call_count, network.call_count) == (1, 1)
    print(json.dumps({"result": result, "observed_calls": list(observed), "guard_controls": [1, 1]}))
'''

CORE_PROBE = r'''
def action():
    for name in sorted(expected):
        importlib.import_module(name)
    loaded = {name for name in sys.modules if name == "cwo_core" or name.startswith("cwo_core.")}
    assert loaded == set(expected), (sorted(set(expected) - loaded), sorted(loaded - set(expected)))
    return {"core_modules": len(expected) - 1, "module_names": sorted(loaded)}
observe(action)
'''

HELP_PROBE = r'''
def action():
    script = root / "scripts" / payload
    sys.argv = [str(script), "--help"]
    output, errors = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
        try:
            runpy.run_path(str(script), run_name="__main__")
        except SystemExit as exc:
            assert exc.code in (None, 0), (exc.code, errors.getvalue())
        else:
            raise AssertionError("CLI --help did not exit through argparse")
    assert "usage:" in output.getvalue().lower(), output.getvalue()
    assert not errors.getvalue(), errors.getvalue()
    return {"help": payload}
observe(action)
'''

RESOURCE_PROBE = r'''
def action():
    import check_installed_skill as checker
    assert Path(checker.__file__).resolve() == root / "scripts/check_installed_skill.py"
    assert checker.REPO_ROOT == root
    checker.load_projection(root)
    for relative, digest in payload["hashes"].items():
        data = (root / relative).read_bytes()
        assert hashlib.sha256(data).hexdigest() == digest, relative
    for relative in payload["json"]:
        json.loads((root / relative).read_text(encoding="utf-8"))
    return {"readable_resources": sorted(payload["hashes"]), "decoded_json": payload["json"]}
observe(action)
'''


class InstalledDependencyClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.install = fixture.InstallerProjectionTests(
            "test_fresh_install_is_the_projection_and_its_resources_are_usable"
        )
        self.install.setUp()
        self.addCleanup(self.install.tearDown)
        self.expected = module_inventory(fixture.ROOT)
        self.env = {**os.environ, "HOME": str(self.install.tmp / "home"),
                    "CODEX_HOME": str(self.install.tmp / "home" / ".codex"),
                    "CODEX_SKILLS_DIR": str(self.install.skills),
                    "PYTHONDONTWRITEBYTECODE": "1"}
        for key in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP"):
            self.env.pop(key, None)
        self.env["PATH"] = str(self.install.shims) + os.pathsep + self.env["PATH"]
        result = self.install.run_installer(extra_env={"PYTHONPATH": "", "PYTHONHOME": "",
                                                      "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(module_inventory(self.install.target), self.expected)

    def child(self, code: str, payload: object = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", "-B", "-c", PREAMBLE + code, str(self.install.target),
             str(fixture.ROOT), json.dumps(self.expected), json.dumps(payload)],
            cwd=self.install.tmp, env=self.env, capture_output=True, text=True, check=False, timeout=60,
        )

    def successful_probe(self, code: str, payload: object = None) -> dict[str, object]:
        result = self.child(code, payload)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["observed_calls"], [0, 0])
        self.assertEqual(report["guard_controls"], [1, 1])
        return report

    def checker(self, *, installed_source: bool = False, listing: bool = False) -> subprocess.CompletedProcess[str]:
        source = self.install.target if installed_source else fixture.ROOT
        args = ["--list-files"] if listing else ["--installed-dir", str(self.install.target), "--check", "--json"]
        return subprocess.run(
            [sys.executable, "-I", "-B", "-c",
             "import runpy,sys; from pathlib import Path; "
             "script=Path(sys.argv.pop(1)); sys.path.insert(0,str(script.parent)); "
             "runpy.run_path(str(script),run_name='__main__')",
             str(source / "scripts/check_installed_skill.py"), "--source-dir", str(source), *args],
            cwd=self.install.tmp, env=self.env, capture_output=True, text=True, check=False, timeout=60,
        )

    def assert_current(self) -> None:
        for installed_source in (False, True):
            result = self.checker(installed_source=installed_source)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "current")
        listing = self.checker(installed_source=True, listing=True)
        self.assertEqual(listing.returncode, 0, listing.stdout + listing.stderr)
        self.assertIn(fixture.PROJECTION, listing.stdout.splitlines())

    def assert_missing(self, relative: str) -> None:
        result = self.checker()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        status = json.loads(result.stdout)
        self.assertEqual(status["status"], "drift")
        self.assertEqual(status["missing_files"], [relative])
        self.assertEqual(status["changed_files"], [])

    def test_all_source_modules_and_bounded_first_run_consumers(self) -> None:
        self.assert_current()
        report = self.successful_probe(CORE_PROBE)["result"]
        self.assertEqual(report["core_modules"], len(self.expected) - 1)
        self.assertEqual(report["module_names"], sorted(self.expected))
        for script in ("check_installed_skill.py", "coach_prompt.py", "route_work.py"):
            with self.subTest(help=script):
                self.successful_probe(HELP_PROBE, script)
        help_result = subprocess.run(
            ["bash", str(self.install.target / "scripts/install.sh"), "--help"],
            cwd=self.install.tmp, env=self.env, capture_output=True, text=True, check=False, timeout=30,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stdout + help_result.stderr)
        self.assertIn("Usage:", help_result.stdout)
        manifest = fixture.checker.build_manifest(fixture.ROOT)
        files = {item["path"]: item["sha256"] for item in manifest["files"]}
        selected = {path for path, kind in fixture.REQUIRED.items() if kind == "file"}
        for directory, kind in fixture.REQUIRED.items():
            if kind == "directory":
                choices = sorted(path for path in files if path.startswith(directory + "/"))
                self.assertTrue(choices, directory)
                selected.add(choices[0])
        selected.update(fixture.CALIBRATION_FILES)
        selected.update(("agents/openai.yaml", fixture.PROJECTION))
        self.successful_probe(RESOURCE_PROBE, {
            "hashes": {path: files[path] for path in sorted(selected)},
            "json": [fixture.PROJECTION, *fixture.CALIBRATION_FILES],
        })
        self.assertFalse((self.install.target / "evaluation").exists())
        self.assertFalse(any(path.startswith("evaluation/") for path in files))
        self.assert_current()

    def test_missing_installed_dependency_breaks_real_checker_and_consumer(self) -> None:
        self.assert_current()
        consumer = "\ndef action():\n import cwo_core.util\n return 'util imported'\nobserve(action)\n"
        self.successful_probe(consumer)
        relative = "scripts/cwo_core/util.py"
        (self.install.target / relative).unlink()
        self.assert_missing(relative)
        for result in (self.checker(installed_source=True), self.child(consumer)):
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("ModuleNotFoundError: No module named 'cwo_core.util'", result.stderr)

    def test_missing_projection_breaks_real_checker_and_resource_consumer(self) -> None:
        self.assert_current()
        consumer = (
            "\ndef action():\n import check_installed_skill as checker\n"
            " checker.load_projection(root)\n return 'projection loaded'\nobserve(action)\n"
        )
        self.successful_probe(consumer)
        (self.install.target / fixture.PROJECTION).unlink()
        self.assert_missing(fixture.PROJECTION)
        result = self.checker(installed_source=True, listing=True)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        diagnostic = "installed projection is missing or not a regular file: "
        self.assertIn(diagnostic + str(self.install.target / fixture.PROJECTION), result.stderr)
        result = self.child(consumer)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ProjectionError: " + diagnostic + str(self.install.target / fixture.PROJECTION), result.stderr)


if __name__ == "__main__":
    unittest.main()
