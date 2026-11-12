"""One installed projection shared by scripts/install.sh and scripts/check_installed_skill.py.

Every install here goes into a disposable temporary skills directory with a disposable HOME;
nothing touches an active Codex home or profile. PATH shims stand in for cp and mv to tamper
with a staged copy or interrupt activation.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_installed_skill as checker  # noqa: E402

SKILL = "complex-work-orchestration"
PROJECTION = "policy/install-projection.yaml"
REQUIRED = {
    "LICENSE": "file", "SECURITY.md": "file", "VERSION": "file", "SKILL.md": "file", "AGENTS.md": "file",
    "README.md": "file", "CHANGELOG.md": "file", "agents": "directory", "policy": "directory",
    "scripts": "directory", "schemas": "directory", "prompts": "directory", "references": "directory",
    "templates": "directory", "experts": "directory", "calibration": "directory", "examples": "directory",
    "docs": "directory",
}
CALIBRATION_FILES = (
    "calibration/skl-return-language-contract-v1.json", "calibration/skl-return-language-corpus-v1.json",
    "calibration/skl-return-language-tuning-v1.json", "calibration/skl-return-language-calibration-report-latest.json",
)
V1_RECORD = {
    "manifest_type": "cwo-installed-skill-status", "version": 1, "generated_at": "2026-01-01T00:00:00+00:00",
    "skill_name": SKILL, "status": "current", "source_version": "0", "installed_version": "0",
    "source_content_sha256": "0" * 64, "installed_content_sha256": "0" * 64,
    "source_file_count": 1, "installed_file_count": 1, "calibration_artifacts": {},
}


def snapshot(root: Path) -> dict[str, tuple[int, str]]:
    """Every path under root with its mode and content (or link target)."""
    result: dict[str, tuple[int, str]] = {}
    if not root.exists():
        return result
    for current, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = Path(current) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                value = os.readlink(path)
            elif stat.S_ISREG(info.st_mode):
                value = hashlib.sha256(path.read_bytes()).hexdigest()
            else:
                value = ""
            result[path.relative_to(root).as_posix()] = (info.st_mode, value)
    return result


# Injects a PermissionError into os.scandir for one directory (CWO_TEST_UNREADABLE, an absolute
# path) in every Python process that has the containing directory on PYTHONPATH, so the
# installer's own checker calls meet an unreadable subtree regardless of the user running them.
UNREADABLE_SITECUSTOMIZE = """\
import errno, os
_target = os.environ.get("CWO_TEST_UNREADABLE")
if _target:
    _real_scandir = os.scandir
    def _scandir(path="."):
        if not isinstance(path, int) and os.path.abspath(os.fspath(path)) == _target:
            raise PermissionError(errno.EACCES, "Permission denied (injected)", os.fspath(path))
        return _real_scandir(path)
    os.scandir = _scandir
"""


def unreadable_env(tmp: Path, target: Path) -> dict[str, str]:
    inject = tmp / "inject"
    inject.mkdir(exist_ok=True)
    (inject / "sitecustomize.py").write_text(UNREADABLE_SITECUSTOMIZE, encoding="utf-8")
    return {"PYTHONPATH": str(inject), "CWO_TEST_UNREADABLE": str(target)}


class OpenSpy:
    """Records every open (os.open, io.open, builtins.open) that reaches one of the given files or
    directories, identified by device and inode, whatever path or directory descriptor was used."""

    def __init__(self, *paths: Path) -> None:
        self.forbidden = {(info.st_dev, info.st_ino) for info in (path.stat() for path in paths)}
        self.hits: list[str] = []
        real_os_open, real_io_open = os.open, io.open

        def check(fd: int, label: object) -> None:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) in self.forbidden:
                self.hits.append(str(label))

        def spy_os_open(path, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
            fd = real_os_open(path, flags, *args, **kwargs)
            check(fd, path)
            return fd

        def spy_io_open(file, *args, **kwargs):  # type: ignore[no-untyped-def]
            handle = real_io_open(file, *args, **kwargs)
            try:
                check(handle.fileno(), file)
            except (AttributeError, OSError, ValueError):
                pass
            return handle

        self.patches = [patch("os.open", spy_os_open), patch("io.open", spy_io_open), patch("builtins.open", spy_io_open)]

    def __enter__(self) -> "OpenSpy":
        for item in self.patches:
            item.start()
        return self

    def __exit__(self, *exc: object) -> None:
        for item in reversed(self.patches):
            item.stop()


def fixture_projection(pairs: list[tuple[str, str]], **overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "version": 1, "description": "Fixture projection.", "skill_name": SKILL,
        "entries": [{"path": path, "kind": kind} for path, kind in pairs], "excluded": [],
    }
    document.update(overrides)
    return document


def make_source(root: Path, document: dict[str, object] | None = None) -> Path:
    (root / "policy").mkdir(parents=True)
    (root / "scripts").mkdir()
    (root / "SKILL.md").write_text("# Skill\n", encoding="utf-8")
    (root / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (root / "scripts" / "helper.py").write_text("print('ok')\n", encoding="utf-8")
    if document is None:
        document = fixture_projection([("SKILL.md", "file"), ("SECURITY.md", "file"), ("scripts", "directory"),
                                       ("policy", "directory")])
    (root / PROJECTION).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return root


class ProjectionDocumentTests(unittest.TestCase):
    def test_projection_keeps_required_resources(self) -> None:
        projection = checker.load_projection(ROOT)
        kinds = {entry["path"]: entry["kind"] for entry in projection["entries"]}
        for path, kind in REQUIRED.items():
            with self.subTest(path=path):
                self.assertEqual(kinds.get(path), kind)
        self.assertEqual(set(kinds), set(REQUIRED))
        self.assertEqual(projection["projection_sha256"], hashlib.sha256((ROOT / PROJECTION).read_bytes()).hexdigest())

    def test_every_tracked_top_level_path_is_projected_or_excluded(self) -> None:
        listed = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=False)
        if listed.returncode != 0:
            self.skipTest("not a Git checkout")
        tracked = {name.decode().split("/", 1)[0] for name in listed.stdout.split(b"\0") if name}
        projection = checker.load_projection(ROOT)
        projected = {entry["path"] for entry in projection["entries"]}
        excluded = {entry["path"] for entry in projection["excluded"]}
        self.assertEqual(projected & excluded, set())
        self.assertEqual(tracked, projected | excluded)
        self.assertLessEqual({"tests", "tools", "CONTRIBUTING.md", "requirements-test.txt"}, excluded)

    def test_checker_manifest_includes_security_policy_and_projection(self) -> None:
        manifest = checker.build_manifest(ROOT)
        paths = {item["path"] for item in manifest["files"]}
        for path in ("SECURITY.md", "LICENSE", "VERSION", "SKILL.md", "AGENTS.md", "agents/openai.yaml", PROJECTION):
            with self.subTest(path=path):
                self.assertIn(path, paths)
        self.assertFalse(any(path.startswith(("tests/", "tools/")) or "__pycache__" in path for path in paths))
        self.assertEqual(manifest["projection"]["path"], PROJECTION)

    def test_malformed_projection_is_refused(self) -> None:
        base = [("SKILL.md", "file"), ("SECURITY.md", "file"), ("scripts", "directory"), ("policy", "directory")]
        cases = {
            "unknown key": (fixture_projection(base, extra=True), "exactly the keys"),
            "version 2": (fixture_projection(base, version=2), "version must be 1"),
            "boolean version": (fixture_projection(base, version=True), "version must be 1"),
            "other skill": (fixture_projection(base, skill_name="other"), "skill_name"),
            "empty description": (fixture_projection(base, description=" "), "description"),
            "no entries": (fixture_projection([]), "non-empty list"),
            "absolute path": (fixture_projection(base + [("/etc", "directory")]), "relative POSIX path"),
            "parent path": (fixture_projection(base + [("../outside", "directory")]), "relative POSIX path"),
            "hidden path": (fixture_projection(base + [(".git", "directory")]), "relative POSIX path"),
            "empty component": (fixture_projection(base + [("docs//x", "file")]), "relative POSIX path"),
            "backslash": (fixture_projection(base + [("docs\\x", "file")]), "relative POSIX path"),
            "duplicate": (fixture_projection(base + [("SKILL.md", "file")]), "overlap"),
            "nested overlap": (fixture_projection(base + [("scripts/helper.py", "file")]), "overlap"),
            "bad kind": (fixture_projection(base + [("docs", "tree")]), "kind must be"),
            "extra entry key": (fixture_projection(base, entries=[{"path": "policy", "kind": "directory", "required": False}]), "exactly the keys"),
            "not self-describing": (fixture_projection([("SKILL.md", "file")]), "inside the projection"),
            "excluded overlaps": (fixture_projection(base, excluded=[{"path": "scripts", "reason": "x"}]), "overlaps entry"),
            "excluded nested": (fixture_projection(base, excluded=[{"path": "tests/x", "reason": "x"}]), "one top-level name"),
            "excluded no reason": (fixture_projection(base, excluded=[{"path": "tests", "reason": ""}]), "reason"),
        }
        for label, (document, message) in cases.items():
            with self.subTest(label), tempfile.TemporaryDirectory() as tmp:
                source = make_source(Path(tmp), document)
                with self.assertRaises(checker.ProjectionError) as raised:
                    checker.load_projection(source)
                self.assertIn(message, str(raised.exception))
        with tempfile.TemporaryDirectory() as tmp:
            source = make_source(Path(tmp))
            (source / PROJECTION).write_text('{"version": 1} # comment\n', encoding="utf-8")
            with self.assertRaisesRegex(checker.ProjectionError, "JSON-compatible YAML"):
                checker.load_projection(source)
            (source / PROJECTION).unlink()
            with self.assertRaisesRegex(checker.ProjectionError, "missing"):
                checker.load_projection(source)
            (source / "elsewhere.yaml").write_text(json.dumps(fixture_projection([("policy", "directory")])))
            (source / PROJECTION).symlink_to(source / "elsewhere.yaml")
            with self.assertRaisesRegex(checker.ProjectionError, "not a regular file"):
                checker.load_projection(source)

    def test_source_that_does_not_satisfy_projection_is_refused(self) -> None:
        def missing(source: Path) -> None:
            (source / "SECURITY.md").unlink()

        def file_is_directory(source: Path) -> None:
            (source / "SECURITY.md").unlink()
            (source / "SECURITY.md").mkdir()
            (source / "SECURITY.md" / "x").write_text("x\n")

        def directory_is_file(source: Path) -> None:
            shutil.rmtree(source / "scripts")
            (source / "scripts").write_text("x\n")

        def entry_symlink(source: Path) -> None:
            (source / "SECURITY.md").unlink()
            (source / "SECURITY.md").symlink_to(source / "SKILL.md")

        def file_symlink_inside(source: Path) -> None:
            (source / "scripts" / "linked.py").symlink_to(source / "SKILL.md")

        def directory_symlink_inside(source: Path) -> None:
            (source / "scripts" / "linked").symlink_to(source / "policy")

        def broken_symlink_inside(source: Path) -> None:
            (source / "scripts" / "dangling").symlink_to(source / "nowhere")

        def fifo_inside(source: Path) -> None:
            os.mkfifo(source / "scripts" / "pipe")

        cases = {
            "missing": (missing, "required projection entry missing: SECURITY.md"),
            "file is a directory": (file_is_directory, "must be a regular file: SECURITY.md"),
            "directory is a file": (directory_is_file, "must be a directory: scripts"),
            "entry symlink": (entry_symlink, "symbolic link: SECURITY.md"),
            "file symlink inside": (file_symlink_inside, "scripts/linked.py"),
            "directory symlink inside": (directory_symlink_inside, "symbolic link: scripts/linked"),
            "broken symlink inside": (broken_symlink_inside, "scripts/dangling"),
            "fifo inside": (fifo_inside, "special file: scripts/pipe"),
        }
        for label, (mutate, message) in cases.items():
            with self.subTest(label), tempfile.TemporaryDirectory() as tmp:
                source = make_source(Path(tmp))
                mutate(source)
                projection = checker.load_projection(source)
                with self.assertRaises(checker.ProjectionError) as raised:
                    checker.iter_manifest_files(source, projection)
                self.assertIn(message, str(raised.exception))
                for flag in ("--list-files", "--list-entries"):
                    result = subprocess.run(
                        [sys.executable, "-B", str(ROOT / "scripts" / "check_installed_skill.py"), "--source-dir", str(source), flag],
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertIn(message, result.stderr)

    def test_existing_install_records_stay_readable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = make_source(Path(tmp) / "source")
            installed = Path(tmp) / "skills" / SKILL
            shutil.copytree(source, installed)
            record = installed / ".cwo-install-manifest.json"
            record.write_text(json.dumps(V1_RECORD), encoding="utf-8")
            status = checker.installed_status(source, installed)
            self.assertEqual(status["status"], "current")
            self.assertEqual(status["previous_install_record"]["version"], 1)
            self.assertTrue(status["previous_install_record"]["readable"])
            self.assertIsNone(status["previous_install_record"]["projection_sha256"])

            checker.write_install_manifest(installed, status)
            written = json.loads(record.read_text(encoding="utf-8"))
            self.assertEqual(written["version"], 2)
            self.assertEqual(written["projection"]["sha256"], status["projection"]["sha256"])
            self.assertEqual(written["source_dir"], str(source))
            again = checker.installed_status(source, installed)
            self.assertEqual(again["previous_install_record"]["version"], 2)
            self.assertEqual(again["previous_install_record"]["projection_sha256"], status["projection"]["sha256"])

            for content in ("not json", json.dumps({**V1_RECORD, "version": 3}), json.dumps({**V1_RECORD, "manifest_type": "x"})):
                with self.subTest(content=content[:20]):
                    record.write_text(content, encoding="utf-8")
                    status = checker.installed_status(source, installed)
                    self.assertEqual(status["status"], "current")
                    self.assertFalse(status["previous_install_record"]["readable"])


    def run_cli(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts" / "check_installed_skill.py"), *args],
            capture_output=True, text=True, check=False, timeout=300, env={**os.environ, **(env or {})},
        )

    def test_non_string_kind_is_a_projection_error(self) -> None:
        base = [("SKILL.md", "file"), ("SECURITY.md", "file"), ("scripts", "directory"), ("policy", "directory")]
        for label, kind in (("list", ["file"]), ("object", {"file": True})):
            with self.subTest(label), tempfile.TemporaryDirectory() as tmp:
                document = fixture_projection(base)
                document["entries"].append({"path": "docs", "kind": kind})  # type: ignore[union-attr]
                source = make_source(Path(tmp) / "source", document)
                with self.assertRaisesRegex(checker.ProjectionError, "kind must be file or directory"):
                    checker.load_projection(source)
                installed = Path(tmp) / "skills" / SKILL
                for args in (("--list-entries",), ("--list-files",), ("--installed-dir", str(installed), "--check")):
                    result = self.run_cli("--source-dir", str(source), *args)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("kind must be file or directory", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)

    def test_unreadable_subtree_is_refused_not_omitted(self) -> None:
        def unreadable(target: Path):  # type: ignore[no-untyped-def]
            real = os.scandir

            def scandir(path="."):  # type: ignore[no-untyped-def]
                if not isinstance(path, int) and os.path.abspath(os.fspath(path)) == str(target):
                    raise PermissionError(13, "Permission denied (injected)", os.fspath(path))
                return real(path)
            return patch("os.scandir", scandir)

        with tempfile.TemporaryDirectory() as tmp:
            source = make_source(Path(tmp) / "source")
            (source / "scripts" / "sub").mkdir()
            (source / "scripts" / "sub" / "deep.py").write_text("x = 1\n", encoding="utf-8")
            installed = Path(tmp) / "skills" / SKILL
            shutil.copytree(source, installed)
            projection = checker.load_projection(source)
            with unreadable(source / "scripts" / "sub"):
                for strict in (True, False):
                    with self.subTest(side="source", strict=strict):
                        with self.assertRaisesRegex(checker.ProjectionError, "cannot read projection directory scripts/sub"):
                            checker.iter_manifest_files(source, projection, strict=strict)
            with unreadable(installed / "scripts" / "sub"):
                with self.assertRaisesRegex(checker.ProjectionError, "cannot read projection directory scripts/sub"):
                    checker.installed_status(source, installed)

            env = unreadable_env(Path(tmp), source / "scripts" / "sub")
            for flag in ("--list-entries", "--list-files"):
                with self.subTest(flag=flag):
                    result = self.run_cli("--source-dir", str(source), flag, env=env)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("cannot read projection directory scripts/sub", result.stderr)
            env = unreadable_env(Path(tmp), installed / "scripts" / "sub")
            result = self.run_cli("--source-dir", str(source), "--installed-dir", str(installed), "--check", env=env)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("cannot read projection directory scripts/sub", result.stderr)

    def test_entry_presence_and_kind_are_checked_without_files(self) -> None:
        pairs = [("SKILL.md", "file"), ("SECURITY.md", "file"), ("scripts", "directory"), ("policy", "directory"),
                 ("templates", "directory")]
        with tempfile.TemporaryDirectory() as tmp:
            source = make_source(Path(tmp) / "source", fixture_projection(pairs))
            (source / "templates").mkdir()
            installed = Path(tmp) / "skills" / SKILL
            shutil.copytree(source, installed)
            self.assertEqual(checker.installed_status(source, installed)["status"], "current")
            (installed / "templates").rmdir()
            status = checker.installed_status(source, installed)
            self.assertEqual(status["status"], "drift")
            self.assertEqual(status["missing_entries"], ["templates"])
            self.assertEqual((status["missing_files"], status["changed_files"], status["extra_files"]), ([], [], []))
            (installed / "templates").write_text("not a directory\n", encoding="utf-8")
            status = checker.installed_status(source, installed)
            self.assertEqual(status["status"], "drift")
            self.assertEqual(status["mismatched_entries"], ["templates"])

        # A supported projection can name a nested file instead of its parent
        # directory. Exercise the actual listing/status interfaces, not only
        # entry_kind's internal return value.
        nested = [("SKILL.md", "file"), ("SECURITY.md", "file"),
                  ("scripts/helper.py", "file"), ("policy", "directory")]
        with tempfile.TemporaryDirectory() as tmp:
            source = make_source(Path(tmp) / "source", fixture_projection(nested))
            installed = Path(tmp) / "skills" / SKILL
            shutil.copytree(source, installed)
            result = self.run_cli("--source-dir", str(source), "--list-files")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(sorted(result.stdout.splitlines()),
                             ["SECURITY.md", "SKILL.md", PROJECTION, "scripts/helper.py"])
            self.assertEqual(checker.installed_status(source, installed)["status"], "current")
            shutil.rmtree(source / "scripts")
            (source / "scripts").write_text("not a directory\n", encoding="utf-8")
            result = self.run_cli("--source-dir", str(source), "--list-files")
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertIn("required projection entry missing: scripts/helper.py", result.stderr)

    def test_installed_metadata_never_opens_a_link_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pairs = [("SKILL.md", "file"), ("SECURITY.md", "file"), ("VERSION", "file"), ("scripts", "directory"),
                     ("policy", "directory"), ("calibration", "directory")]
            source = make_source(Path(tmp) / "source", fixture_projection(pairs))
            (source / "VERSION").write_text("1.0.0\n", encoding="utf-8")
            (source / "calibration").mkdir()
            outside = Path(tmp) / "outside"
            (outside / "calibration").mkdir(parents=True)
            (outside / "VERSION").write_text("EXTERNAL-SECRET\n", encoding="utf-8")
            targets = [outside / "VERSION", outside / "calibration"]
            for name in CALIBRATION_FILES:
                (source / name).write_text('{"artifact": "source"}\n', encoding="utf-8")
                (outside / name).write_text('{"artifact": "source"}\n', encoding="utf-8")
                targets.append(outside / name)
            contract = CALIBRATION_FILES[0]

            def version_and_directory_links(installed: Path) -> None:
                (installed / "VERSION").unlink()
                (installed / "VERSION").symlink_to(outside / "VERSION")
                shutil.rmtree(installed / "calibration")
                (installed / "calibration").symlink_to(outside / "calibration")

            def file_link(installed: Path) -> None:
                (installed / contract).unlink()
                (installed / contract).symlink_to(outside / contract)

            for label, mutate in (("VERSION and calibration directory", version_and_directory_links),
                                  ("calibration file", file_link)):
                with self.subTest(label):
                    installed = Path(tmp) / label.replace(" ", "-") / SKILL
                    shutil.copytree(source, installed)
                    self.assertEqual(checker.installed_status(source, installed)["installed_version"], "1.0.0")
                    mutate(installed)
                    with OpenSpy(*targets) as spy:
                        status = checker.installed_status(source, installed)
                    self.assertEqual(spy.hits, [])
                    self.assertEqual(status["status"], "drift")
                    self.assertIsNone(status["calibration_artifacts"]["installed"]["contract"])
                    self.assertIsNotNone(status["calibration_artifacts"]["source"]["contract"])
                    self.assertNotEqual(status["installed_version"], "EXTERNAL-SECRET")
                    result = self.run_cli("--source-dir", str(source), "--installed-dir", str(installed), "--json")
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotIn("EXTERNAL-SECRET", result.stdout)
            self.assertIsNone(checker.installed_status(source, Path(tmp) / "VERSION-and-calibration-directory" / SKILL)["installed_version"])

            # The source side reads its projection without following a linked policy directory.
            linked = Path(tmp) / "linked-source"
            shutil.copytree(source, linked)
            shutil.move(str(linked / "policy"), str(outside / "policy"))
            (linked / "policy").symlink_to(outside / "policy")
            with OpenSpy(outside / "policy" / "install-projection.yaml") as spy:
                with self.assertRaisesRegex(checker.ProjectionError, "missing or not a regular file"):
                    checker.load_projection(linked)
            self.assertEqual(spy.hits, [])


    def test_installed_symlinks_read_as_drift_and_are_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = make_source(Path(tmp) / "source")
            installed = Path(tmp) / "skills" / SKILL
            shutil.copytree(source, installed)
            self.assertEqual(checker.installed_status(source, installed)["status"], "current")
            (installed / "scripts" / "helper.py").unlink()
            (installed / "scripts" / "helper.py").symlink_to(source / "scripts" / "helper.py")
            (installed / "scripts" / "extra").symlink_to(source / "policy")
            status = checker.installed_status(source, installed)
        self.assertEqual(status["status"], "drift")
        self.assertIn("scripts/helper.py", status["changed_files"])
        self.assertIn("scripts/extra", status["extra_files"])


class InstallerProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.skills = self.tmp / "skills"
        self.target = self.skills / SKILL
        self.backups = self.tmp / "skill-backups"
        self.shims = self.tmp / "shims"
        self.shims.mkdir()
        (self.tmp / "home").mkdir()
        # A stub bd keeps the installer's Beads check hermetic; a real bd may write under HOME.
        bd = self.shims / "bd"
        bd.write_text('#!/bin/sh\n[ "$1" = version ] || exit 64\nprintf "fixture Beads CLI\\n"\n', encoding="utf-8")
        bd.chmod(0o755)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_installer(
        self, *args: str, source: Path = ROOT, extra_env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        env = {**os.environ, "HOME": str(self.tmp / "home"), "SKILL_VALIDATOR": str(self.tmp / "no-validator.py"),
               **(extra_env or {})}
        env.pop("CODEX_HOME", None)
        env.pop("CODEX_SKILLS_DIR", None)
        env["PATH"] = str(self.shims) + os.pathsep + env["PATH"]
        return subprocess.run(
            ["bash", str(source / "scripts" / "install.sh"), "--skills-dir", str(self.skills), "--yes", *args],
            cwd=self.tmp, env=env, capture_output=True, text=True, check=False, timeout=300,
        )

    def run_checker(self, *args: str, source: Path = ROOT) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(source / "scripts" / "check_installed_skill.py"), *args],
            capture_output=True, text=True, check=False, timeout=300,
        )

    def install(self) -> dict[str, object]:
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads((self.target / ".cwo-install-manifest.json").read_text(encoding="utf-8"))

    def write_shim(self, name: str, body: str) -> None:
        real = shutil.which(name)
        self.assertIsNotNone(real)
        path = self.shims / name
        path.write_text(f"#!/bin/sh\nREAL={real}\n{body}", encoding="utf-8")
        path.chmod(0o755)

    def copy_source(self) -> Path:
        """A disposable source checkout holding the required resources this file expects."""
        source = self.tmp / "source"
        source.mkdir()
        for name, kind in REQUIRED.items():
            if kind == "file":
                shutil.copy2(ROOT / name, source / name)
            else:
                shutil.copytree(ROOT / name, source / name, ignore=shutil.ignore_patterns("__pycache__"))
        return source

    def leftovers(self) -> list[str]:
        stages = [path.name for path in self.skills.glob(f".{SKILL}.stage.*")] if self.skills.exists() else []
        backups = [path.name for path in self.backups.glob(f"{SKILL}.prev.*")] if self.backups.exists() else []
        return stages + backups

    def test_fresh_install_is_the_projection_and_its_resources_are_usable(self) -> None:
        record = self.install()
        expected = checker.build_manifest(ROOT)
        installed = {
            path for path, (mode, _) in snapshot(self.target).items()
            if stat.S_ISREG(mode) and path != ".cwo-install-manifest.json"
        }
        self.assertEqual(installed, {item["path"] for item in expected["files"]})
        self.assertEqual(record["version"], 2)
        self.assertEqual(record["status"], "current")
        self.assertEqual(record["installed_content_sha256"], expected["content_sha256"])
        self.assertEqual(record["projection"]["sha256"], hashlib.sha256((ROOT / PROJECTION).read_bytes()).hexdigest())
        self.assertEqual(record["source_dir"], str(ROOT.resolve()))
        for name in ("SECURITY.md", "LICENSE", "VERSION"):
            self.assertEqual((self.target / name).read_bytes(), (ROOT / name).read_bytes())
        self.assertTrue(os.access(self.target / "scripts" / "install.sh", os.X_OK))
        check = self.run_checker("--skills-dir", str(self.skills), "--check")
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
        # The installed tree carries its own projection and imports: its checker verifies itself.
        own = self.run_checker("--source-dir", str(self.target), "--installed-dir", str(self.target), "--check", source=self.target)
        self.assertEqual(own.returncode, 0, own.stdout + own.stderr)
        self.assertEqual(self.leftovers(), [])

    def test_replacement_install_yields_the_same_manifest_and_keeps_a_backup(self) -> None:
        first = self.install()
        (self.target / "LOCAL_MARKER").write_text("local\n", encoding="utf-8")
        second = self.install()
        self.assertEqual(first["installed_content_sha256"], second["installed_content_sha256"])
        self.assertEqual(first["projection"], second["projection"])
        self.assertFalse((self.target / "LOCAL_MARKER").exists())
        backups = sorted(self.backups.glob(f"{SKILL}.prev.*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual((backups[0] / "LOCAL_MARKER").read_text(encoding="utf-8"), "local\n")
        self.assertEqual(json.loads((backups[0] / ".cwo-install-manifest.json").read_text())["version"], 2)
        check = self.run_checker("--skills-dir", str(self.skills), "--check")
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)

    def test_security_policy_drift_is_detected(self) -> None:
        self.install()
        with (self.target / "SECURITY.md").open("a", encoding="utf-8") as handle:
            handle.write("drift\n")
        check = self.run_checker("--skills-dir", str(self.skills), "--check", "--json")
        self.assertEqual(check.returncode, 1, check.stdout + check.stderr)
        status = json.loads(check.stdout)
        self.assertEqual(status["status"], "drift")
        self.assertEqual(status["changed_files"], ["SECURITY.md"])
        (self.target / "SECURITY.md").unlink()
        status = json.loads(self.run_checker("--skills-dir", str(self.skills), "--json").stdout)
        self.assertEqual(status["missing_files"], ["SECURITY.md"])

    def test_missing_required_entry_refuses_install_and_dry_run_without_change(self) -> None:
        self.install()
        (self.target / "LOCAL_MARKER").write_text("local\n", encoding="utf-8")
        source = self.copy_source()
        (source / "SECURITY.md").unlink()
        before = snapshot(self.tmp / "skills"), snapshot(self.backups)
        for args in ((), ("--dry-run",)):
            with self.subTest(args=args):
                result = self.run_installer(*args, source=source)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("required projection entry missing: SECURITY.md", result.stderr)
                self.assertIn("nothing was installed", result.stderr)
                self.assertEqual((snapshot(self.tmp / "skills"), snapshot(self.backups)), before)
                self.assertEqual(self.leftovers(), [])

    def test_tampered_staged_copy_is_never_activated(self) -> None:
        tamper = '"$REAL" "$@" || exit $?\nfor last; do :; done\ncase "$last" in */SECURITY.md) printf "tampered\\n" >> "$last";; esac\n'
        self.write_shim("cp", tamper)
        fresh = self.run_installer()
        self.assertNotEqual(fresh.returncode, 0, fresh.stdout)
        self.assertIn("nothing was activated", fresh.stderr)
        self.assertIn("SECURITY.md", fresh.stdout)
        self.assertFalse(self.target.exists())
        self.assertEqual(self.leftovers(), [])

        (self.shims / "cp").unlink()
        self.install()
        before = snapshot(self.target)
        self.write_shim("cp", tamper)
        replacement = self.run_installer()
        self.assertNotEqual(replacement.returncode, 0, replacement.stdout)
        self.assertIn("nothing was activated", replacement.stderr)
        self.assertEqual(snapshot(self.target), before)
        self.assertEqual(self.leftovers(), [])

    def test_interrupted_activation_rolls_back_to_the_previous_install(self) -> None:
        self.install()
        (self.target / "LOCAL_MARKER").write_text("local\n", encoding="utf-8")
        before = snapshot(self.target)
        self.write_shim("mv", f'for last; do :; done\ncase "$*" in *.{SKILL}.stage.*) '
                              f'case "$last" in */{SKILL}) exit 1;; esac;; esac\nexec "$REAL" "$@"\n')
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("could not activate staged install", result.stderr)
        self.assertEqual(snapshot(self.target), before)
        self.assertEqual(self.leftovers(), [])

    def test_signal_after_the_previous_install_moved_restores_it(self) -> None:
        # The mv shim lets the previous install move to its backup, then sends TERM to the
        # installer: the move itself succeeded, so only the signal path can restore it.
        self.install()
        (self.target / "LOCAL_MARKER").write_text("local\n", encoding="utf-8")
        before = snapshot(self.target)
        self.write_shim("mv", f'for last; do :; done\ncase "$last" in */skill-backups/{SKILL}.prev.*) '
                              f'"$REAL" "$@" || exit $?; kill -TERM "$PPID"; exit 0;; esac\nexec "$REAL" "$@"\n')
        result = self.run_installer()
        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        self.assertIn("Restored the previous install", result.stderr)
        self.assertEqual(snapshot(self.target), before)
        self.assertEqual(self.leftovers(), [])

    def test_kill_after_the_previous_install_moved_leaves_the_documented_state(self) -> None:
        self.install()
        (self.target / "LOCAL_MARKER").write_text("local\n", encoding="utf-8")
        before = snapshot(self.target)
        self.write_shim("mv", f'for last; do :; done\ncase "$last" in */skill-backups/{SKILL}.prev.*) '
                              f'"$REAL" "$@" || exit $?; kill -KILL "$PPID"; exit 0;; esac\nexec "$REAL" "$@"\n')
        result = self.run_installer()
        self.assertEqual(result.returncode, -9, result.stdout + result.stderr)
        (self.shims / "mv").unlink()
        # As documented in --help: no active install, the previous install intact in the backup
        # directory, and the verified staged copy left in the skills directory.
        self.assertFalse(self.target.exists())
        backups = sorted(self.backups.glob(f"{SKILL}.prev.*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(snapshot(backups[0]), before)
        stages = sorted(self.skills.glob(f".{SKILL}.stage.*"))
        self.assertEqual(len(stages), 1)
        staged = self.run_checker("--installed-dir", str(stages[0]), "--check")
        self.assertEqual(staged.returncode, 0, staged.stdout + staged.stderr)
        check = self.run_checker("--skills-dir", str(self.skills), "--check")
        self.assertEqual(check.returncode, 1, check.stdout + check.stderr)
        self.assertIn("status: missing", check.stdout)
        usage = self.run_installer("--help")
        self.assertIn("SIGKILL", usage.stdout)
        self.assertIn("previous install is intact in the backup directory", usage.stdout)
        # Recovery by rerunning: the leftover stage is reported, a verified install becomes active
        # and the backup from the interrupted run is kept.
        rerun = self.run_installer()
        self.assertEqual(rerun.returncode, 0, rerun.stdout + rerun.stderr)
        self.assertIn(f"staging directory left by an interrupted install (not active; delete it once no other install is running): {stages[0]}", rerun.stdout)
        self.assertEqual(self.run_checker("--skills-dir", str(self.skills), "--check").returncode, 0)
        self.assertEqual(sorted(self.backups.glob(f"{SKILL}.prev.*")), backups)
        self.assertEqual(snapshot(backups[0]), before)

    def test_unreadable_source_subtree_refuses_install_without_change(self) -> None:
        self.install()
        (self.target / "LOCAL_MARKER").write_text("local\n", encoding="utf-8")
        before = snapshot(self.skills), snapshot(self.backups)
        env = unreadable_env(self.tmp, ROOT / "scripts" / "cwo_core")
        for args in ((), ("--dry-run",)):
            with self.subTest(args=args):
                result = self.run_installer(*args, extra_env=env)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("cannot read projection directory scripts/cwo_core", result.stderr)
                self.assertIn("nothing was installed", result.stderr)
                self.assertEqual((snapshot(self.skills), snapshot(self.backups)), before)
                self.assertEqual(self.leftovers(), [])

    def test_empty_required_directory_is_installed_and_its_removal_is_drift(self) -> None:
        source = self.copy_source()
        shutil.rmtree(source / "examples")
        (source / "examples").mkdir()
        result = self.run_installer(source=source)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.target / "examples").is_dir())
        self.assertEqual(list((self.target / "examples").iterdir()), [])
        check = self.run_checker("--source-dir", str(source), "--skills-dir", str(self.skills), "--check")
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
        (self.target / "examples").rmdir()
        check = self.run_checker("--source-dir", str(source), "--skills-dir", str(self.skills), "--check", "--json")
        self.assertEqual(check.returncode, 1, check.stdout + check.stderr)
        status = json.loads(check.stdout)
        self.assertEqual(status["status"], "drift")
        self.assertEqual(status["missing_entries"], ["examples"])

    def test_dry_run_over_an_existing_install_changes_nothing(self) -> None:
        self.install()
        before = snapshot(self.tmp)
        result = self.run_installer("--dry-run")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Would move existing install to backup", result.stdout)
        self.assertEqual(snapshot(self.tmp), before)

    def test_existing_install_from_an_older_layout_is_reported_and_replaced(self) -> None:
        self.install()
        (self.target / "SECURITY.md").unlink()
        (self.target / ".cwo-install-manifest.json").write_text(json.dumps(V1_RECORD), encoding="utf-8")
        status = json.loads(self.run_checker("--skills-dir", str(self.skills), "--json").stdout)
        self.assertEqual(status["status"], "drift")
        self.assertEqual(status["missing_files"], ["SECURITY.md"])
        self.assertEqual(status["previous_install_record"]["version"], 1)
        before = snapshot(self.tmp)
        dry_run = self.run_installer("--dry-run")
        self.assertEqual(dry_run.returncode, 0, dry_run.stdout + dry_run.stderr)
        self.assertIn("Existing install record: version 1", dry_run.stdout)
        self.assertEqual(snapshot(self.tmp), before)

        record = self.install()
        self.assertEqual(record["version"], 2)
        self.assertTrue((self.target / "SECURITY.md").is_file())
        backups = sorted(self.backups.glob(f"{SKILL}.prev.*"))
        self.assertEqual(len(backups), 1)
        self.assertFalse((backups[0] / "SECURITY.md").exists())
        self.assertEqual(json.loads((backups[0] / ".cwo-install-manifest.json").read_text()), V1_RECORD)


    def test_missing_required_entry_refuses_a_fresh_install(self) -> None:
        source = self.copy_source()
        shutil.rmtree(source / "calibration")
        result = self.run_installer(source=source)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("required projection entry missing: calibration", result.stderr)
        self.assertFalse(self.target.exists())
        self.assertEqual(self.leftovers(), [])


if __name__ == "__main__":
    unittest.main()
