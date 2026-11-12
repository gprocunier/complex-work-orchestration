"""Retained-record checks use real disposable installer output without its source checkout."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest
from typing import Callable, Iterator, NamedTuple

from tests import test_install_projection as fixture


PROBE = r'''
import contextlib
import errno
import importlib
import io
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path
from unittest.mock import patch

root = Path(sys.argv[1])
source = Path(sys.argv[2])
flags = json.loads(sys.argv[3])
deny = sys.argv[4]
assert not any(name == "cwo_core" or name.startswith("cwo_core.") for name in sys.modules)
assert str(source / "scripts") not in sys.path
sys.path.insert(0, str(root / "scripts"))
checker = importlib.import_module("check_installed_skill")
assert Path(checker.__file__).resolve() == root / "scripts/check_installed_skill.py"
for name, module in list(sys.modules.items()):
    if name == "cwo_core" or name.startswith("cwo_core."):
        assert Path(module.__file__).resolve().is_relative_to(root / "scripts"), name

opened, listed, descriptors = [], [], {}
real_os_open, real_file_open, real_scandir = os.open, io.open, os.scandir
def under_root(path):
    candidate = Path(os.fsdecode(path))
    assert candidate.is_absolute() and candidate.is_relative_to(root), candidate
    assert ".." not in candidate.parts, candidate
    return candidate

def guarded_os_open(path, flags, mode=0o777, *, dir_fd=None):
    assert not (flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
    if dir_fd is None:
        candidate = under_root(path)
    else:
        assert dir_fd in descriptors, dir_fd
        relative = Path(os.fsdecode(path))
        assert not relative.is_absolute() and ".." not in relative.parts, relative
        assert flags & os.O_NOFOLLOW
        candidate = under_root(descriptors[dir_fd] / relative)
    opened.append(str(candidate))
    if deny and candidate == root / deny:
        raise PermissionError(errno.EACCES, "Permission denied (injected)", str(candidate))
    fd = real_os_open(path, flags, mode, dir_fd=dir_fd)
    descriptors[fd] = candidate
    return fd

def guarded_file_open(file, mode="r", *args, **kwargs):
    assert not any(char in mode for char in "wax+"), mode
    if isinstance(file, int):
        assert file in descriptors, file
    else:
        opened.append(str(under_root(file)))
    return real_file_open(file, mode, *args, **kwargs)

def guarded_scandir(path="."):
    listed.append(str(under_root(path)))
    return real_scandir(path)

sys.argv = [str(root / "scripts/check_installed_skill.py"), "--record-check", "--installed-dir", str(root), "--json", *flags]
output, errors = io.StringIO(), io.StringIO()
with patch("os.open", guarded_os_open), patch("io.open", guarded_file_open), \
        patch("builtins.open", guarded_file_open), patch("os.scandir", guarded_scandir), \
        patch.object(checker, "atomic_write_text", side_effect=AssertionError("write guard reached")) as writer, \
        patch("subprocess.Popen", side_effect=AssertionError("process guard reached")) as process, \
        patch("urllib.request.urlopen", side_effect=AssertionError("urlopen guard reached")) as network:
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
        try:
            code = checker.main()
        except SystemExit as exc:
            code = exc.code
    observed = [writer.call_count, process.call_count, network.call_count]
    assert observed == [0, 0, 0], observed
    for call in (lambda: checker.atomic_write_text(root / "never-write", "x"),
                 lambda: subprocess.Popen(["never-start"]),
                 lambda: urllib.request.urlopen("https://never-connect.invalid")):
        try:
            call()
        except AssertionError:
            pass
        else:
            raise AssertionError("guard control did not refuse")
    controls = [writer.call_count, process.call_count, network.call_count]
    assert controls == [1, 1, 1], controls
print(json.dumps({
    "exit": code, "stdout": output.getvalue(), "stderr": errors.getvalue(),
    "opened": opened, "listed": listed, "observed": observed, "controls": controls,
}))
'''


class RecordMutationCase(NamedTuple):
    original: str
    subtest: dict
    mutate: Callable[[InstallRecordVerificationTests], None] | None
    status: str
    code: str
    deny: str = ""
    expected_count: int | None = None
    legacy_version: int | None = None


def _append_valid_markdown(case) -> None:
    path = case.install.target / "SECURITY.md"
    path.write_bytes(path.read_bytes() + b"\nAdditional valid Markdown.\n")


def _remove_installed_path(case, relative: str) -> None:
    path = case.install.target / relative
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def _replace_installed_link(case, relative: str) -> None:
    path = case.install.target / relative
    outside = case.install.tmp / ("outside-" + path.name)
    outside.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(outside)


def _record_fifo(case) -> None:
    path = case.install.target / fixture.checker.INSTALL_MANIFEST_NAME
    path.unlink()
    os.mkfifo(path)


def _stored_binding(case, field, value) -> None:
    if field == "projection":
        case.edit_record(("projection", "sha256"), value)
    else:
        case.edit_record((field,), value)
        case.edit_record((field.replace("installed_", "source_"),), value)


def _weaken_projection(case, weaken: bool) -> None:
    path = case.install.target / fixture.PROJECTION
    projection = json.loads(path.read_text(encoding="utf-8"))
    projection["description"] += " Changed."
    if weaken:
        projection["entries"] = [entry for entry in projection["entries"] if entry["path"] != "SECURITY.md"]
        (case.install.target / "SECURITY.md").unlink()
    path.write_text(json.dumps(projection), encoding="utf-8")


def _non_utf8_file(case) -> None:
    name = os.fsencode(case.install.target / "scripts") + b"/\xff.txt"
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, b"ordinary content\n")
    finally:
        os.close(descriptor)


def _retained_record_rows(case) -> Iterator[RecordMutationCase]:
    yield RecordMutationCase("test_valid_changed_bytes_are_detected_by_the_retained_aggregate", {},
                             _append_valid_markdown, "record-drift", "content-aggregate-mismatch",
                             expected_count=case.record["installed_file_count"])
    for relative in ("SECURITY.md", "references/contractor-brief.md", "templates"):
        code = "missing-required-entry" if relative != "references/contractor-brief.md" else "content-aggregate-mismatch"
        yield RecordMutationCase("test_missing_required_and_nested_files", {"relative": relative},
                                 lambda case, relative=relative: _remove_installed_path(case, relative), "record-drift", code)
    for relative in ("SECURITY.md", fixture.checker.INSTALL_MANIFEST_NAME):
        yield RecordMutationCase("test_symlinks_and_nonregular_record", {"relative": relative},
                                 lambda case, relative=relative: _replace_installed_link(case, relative),
                                 "record-unverifiable" if relative.startswith(".") else "record-drift",
                                 "record-not-regular" if relative.startswith(".") else "invalid-installed-file")
    yield RecordMutationCase("test_symlinks_and_nonregular_record", {"kind": "fifo"}, _record_fifo,
                             "record-unverifiable", "record-not-regular")
    yield RecordMutationCase("test_missing_unreadable_and_invalid_record_json", {"kind": "missing"},
                             lambda case: (case.install.target / fixture.checker.INSTALL_MANIFEST_NAME).unlink(),
                             "record-unverifiable", "record-missing")
    yield RecordMutationCase("test_missing_unreadable_and_invalid_record_json", {"kind": "unreadable record"}, None,
                             "record-unverifiable", "record-unreadable", deny=fixture.checker.INSTALL_MANIFEST_NAME)
    yield RecordMutationCase("test_missing_unreadable_and_invalid_record_json", {"kind": "unreadable installed"}, None,
                             "record-unverifiable", "installed-unreadable", deny="SECURITY.md")
    for data in (b"not json", b"\xff", b"[]", json.dumps(case.record)[:-1].encode() + b', "version": 2}'):
        yield RecordMutationCase("test_missing_unreadable_and_invalid_record_json", {"data": data[:30]},
                                 lambda case, data=data: (case.install.target / fixture.checker.INSTALL_MANIFEST_NAME).write_bytes(data),
                                 "record-unverifiable", "invalid-record")
    cases = [
        (("version",), True),
        (("version",), 2.0),
        (("installed_file_count",), True),
        (("installed_file_count",), 1.0),
        (("installed_file_count",), -1),
        (("source_file_count",), "1"),
        (("installed_content_sha256",), "g" * 64),
        (("source_content_sha256",), "0" * 63),
        (("projection", "sha256"), "A" * 64),
        (("projection", "version"), True),
        (("projection", "version"), 1.0),
        (("projection", "path"), "/outside"),
        (("projection", "entries"), ["../outside"]),
        (("projection", "entries"), [True]),
        (("status",), "drift"),
        (("calibration_artifacts", "installed", "contract"), False),
    ]
    for path, value in cases:
        yield RecordMutationCase("test_record_schema_and_legacy_refusals", {"path": path, "value": value},
                                 lambda case, path=path, value=value: case.edit_record(path, value),
                                 "record-unverifiable", "invalid-record")
    for version in (1, 3):
        yield RecordMutationCase("test_record_schema_and_legacy_refusals", {"version": version},
                                 lambda case, version=version: case.edit_record(("version",), version),
                                 "record-unverifiable", "unsupported-record-version", legacy_version=1 if version == 1 else None)
    for field, value, code in (
        ("installed_file_count", case.record["installed_file_count"] + 1, "file-count-mismatch"),
        ("installed_content_sha256", "0" * 64, "content-aggregate-mismatch"),
        ("projection", "0" * 64, "projection-mismatch"),
    ):
        yield RecordMutationCase("test_stored_count_hash_and_projection_identity_are_binding", {"field": field},
                                 lambda case, field=field, value=value: _stored_binding(case, field, value), "record-drift", code)
    for weaken in (False, True):
        yield RecordMutationCase("test_edited_or_weakened_projection_is_not_used_to_shorten_verification", {"weaken": weaken},
                                 lambda case, weaken=weaken: _weaken_projection(case, weaken), "record-drift", "projection-mismatch")
    yield RecordMutationCase("test_edited_or_weakened_projection_is_not_used_to_shorten_verification", {"kind": "missing projection"},
                             lambda case: (case.install.target / fixture.PROJECTION).unlink(),
                             "record-unverifiable", "installed-projection-unverifiable")
    yield RecordMutationCase("test_non_utf8_filename_refuses_with_json_without_writes", {}, _non_utf8_file,
                             "record-unverifiable", "installed-unreadable")


class InstallRecordVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.install = fixture.InstallerProjectionTests(
            "test_fresh_install_is_the_projection_and_its_resources_are_usable"
        )
        self.install.setUp()
        self.addCleanup(self.install.tearDown)
        self.prepare_installed_image()
        self.record = json.loads((self.install.target / fixture.checker.INSTALL_MANIFEST_NAME).read_text(encoding="utf-8"))
        self.assertEqual(self.record["version"], 2)
        self.assertEqual(self.record["status"], "current")
        self.retired = self.source.with_name("retired-source")
        self.source.rename(self.retired)
        self.assertFalse(self.source.exists())
        self.pristine = self.install.tmp / "pristine"
        shutil.copytree(self.install.target, self.pristine)
        self.env = {**os.environ,
                    "HOME": str(self.install.tmp / "home"), "CODEX_HOME": str(self.install.tmp / "home/.codex"),
                    "CODEX_SKILLS_DIR": str(self.install.skills), "PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C", "LANG": "C"}
        for key in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP"):
            self.env.pop(key, None)

    @classmethod
    def installed_seed(cls):
        if "_installed_seed" not in cls.__dict__:
            control = cls("runTest")
            install = fixture.InstallerProjectionTests(
                "test_fresh_install_is_the_projection_and_its_resources_are_usable"
            )
            install.setUp()
            cls.addClassCleanup(install.tearDown)
            source = install.copy_source()
            result = install.run_installer(
                source=source, extra_env={"PYTHONPATH": "", "PYTHONHOME": "", "PYTHONDONTWRITEBYTECODE": "1"},
            )
            control.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            cls._installed_seed = install, source, fixture.snapshot(source), fixture.snapshot(install.target)
            cls.addClassCleanup(delattr, cls, "_installed_seed")
            cls.addClassCleanup(cls.verify_installed_seed)
        return cls._installed_seed

    @classmethod
    def verify_installed_seed(cls):
        install, source, source_image, target_image = cls._installed_seed
        control = cls("runTest")
        control.assertEqual(fixture.snapshot(source), source_image)
        control.assertEqual(fixture.snapshot(install.target), target_image)

    def copy_seed_tree(self, seed, destination, expected):
        shutil.copytree(seed, destination)
        self.assertEqual(fixture.snapshot(destination), expected)
        self.assertEqual(destination.stat().st_mode, seed.stat().st_mode)
        for relative, (mode, _) in expected.items():
            if fixture.stat.S_ISREG(mode):
                self.assertFalse(os.path.samefile(seed / relative, destination / relative))
        return destination

    def prepare_installed_image(self):
        # The original genuine-install control still executes the actual
        # installer. Record-reading cases copy its real immutable seed instead.
        if self._testMethodName == "test_genuine_install_without_source_checkout":
            self.source = self.install.copy_source()
            result = self.install.run_installer(
                source=self.source, extra_env={"PYTHONPATH": "", "PYTHONHOME": "", "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return
        install, source, source_image, target_image = self.installed_seed()
        self.source = self.copy_seed_tree(source, self.install.tmp / "source", source_image)
        self.install.skills.mkdir()
        self.copy_seed_tree(install.target, self.install.target, target_image)
        path = self.install.target / fixture.checker.INSTALL_MANIFEST_NAME
        record = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(record["source_dir"], str(source))
        # This inert coordinate is case-local; all content hashes and the
        # original real install's record fields otherwise remain unchanged.
        record["source_dir"] = str(self.source)
        path.write_text(json.dumps(record), encoding="utf-8")

    def probe(self, *flags: str, deny: str = "") -> dict[str, object]:
        before = fixture.snapshot(self.install.tmp)
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", PROBE, str(self.install.target), str(self.source), json.dumps(flags), deny],
            cwd=self.install.tmp / "home", env=self.env, capture_output=True, text=True, check=False, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(fixture.snapshot(self.install.tmp), before)
        report = json.loads(result.stdout)
        self.assertEqual(report["observed"], [0, 0, 0])
        self.assertEqual(report["controls"], [1, 1, 1])
        self.assertNotIn("Traceback", report["stderr"])
        return report

    def positive(self) -> dict[str, object]:
        shutil.rmtree(self.install.target)
        shutil.copytree(self.pristine, self.install.target)
        report = self.probe()
        self.assertEqual(report["exit"], 0, report)
        status = json.loads(report["stdout"])
        self.assertEqual(status["status"], "record-consistent")
        self.assertEqual(status["recorded_content_sha256"], self.record["installed_content_sha256"])
        self.assertEqual(status["installed_content_sha256"], self.record["installed_content_sha256"])
        self.assertIn(str(self.install.target / fixture.checker.INSTALL_MANIFEST_NAME), report["opened"])
        self.assertIn(str(self.install.target / fixture.PROJECTION), report["opened"])
        return status

    def negative(self, status: str, code: str, *, deny: str = "") -> dict[str, object]:
        report = self.probe(deny=deny)
        self.assertEqual(report["exit"], 1 if status == "record-drift" else 2, report)
        result = json.loads(report["stdout"])
        self.assertEqual(result["status"], status)
        self.assertIn(code, [issue["code"] for issue in result["errors"]])
        return result

    def edit_record(self, path: tuple[str, ...], value: object) -> None:
        target = self.install.target / fixture.checker.INSTALL_MANIFEST_NAME
        record = json.loads(target.read_text(encoding="utf-8"))
        cursor = record
        for key in path[:-1]:
            cursor = cursor[key]
        cursor[path[-1]] = value
        target.write_text(json.dumps(record), encoding="utf-8")

    def assert_record_cli(self, expected_exit: int, expected_status: str, error: str | None = None) -> dict:
        """The installed public CLI must return structured refusal, not a traceback."""
        before = fixture.snapshot(self.install.tmp)
        bootstrap = (
            "import runpy,sys;sys.path.insert(0,sys.argv.pop(1));"
            "runpy.run_module('check_installed_skill',run_name='__main__')"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", bootstrap, str(self.install.target / "scripts"),
             "--record-check", "--installed-dir", str(self.install.target), "--json"],
            cwd=self.install.tmp / "home", env=self.env, capture_output=True, text=True,
            check=False, timeout=60,
        )
        diagnostic = json.dumps({"stdout": result.stdout, "stderr": result.stderr})
        self.assertEqual(fixture.snapshot(self.install.tmp), before)
        self.assertNotIn("Traceback", result.stderr, diagnostic)
        self.assertEqual(result.returncode, expected_exit, diagnostic)
        self.assertEqual(result.stderr, "", diagnostic)
        status = json.loads(result.stdout)
        self.assertEqual(status["status"], expected_status)
        if error is not None:
            self.assertIn(error, [issue["code"] for issue in status["errors"]])
        return status

    def test_genuine_install_without_source_checkout(self) -> None:
        status = self.positive()
        self.assertEqual(status["recorded_file_count"], self.record["installed_file_count"])
        self.assertEqual(status["installed_file_count"], self.record["installed_file_count"])
        self.assertIn("both can be rewritten", status["verification_scope"])
        self.assertNotIn("source_dir", status)

        # None is a legitimate producer output when an optional calibration
        # artifact is absent. Produce it through the real private installer,
        # then retire that source before exercising the installed consumer.
        optional = self.retired / fixture.CALIBRATION_FILES[-1]
        optional.unlink()
        installed = self.install.run_installer(
            source=self.retired,
            extra_env={"PYTHONPATH": "", "PYTHONHOME": "", "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        self.retired.rename(self.retired.with_name("retired-optional-source"))
        record = json.loads((self.install.target / fixture.checker.INSTALL_MANIFEST_NAME).read_text())
        for side in ("source", "installed"):
            self.assertIsNone(record["calibration_artifacts"][side]["latest_report"])
        self.assert_record_cli(0, "record-consistent")
        for side in ("source", "installed"):
            self.edit_record(("calibration_artifacts", side, "latest_report"), "malformed-hash")
        self.assert_record_cli(2, "record-unverifiable", "invalid-record")

    def test_retained_record_mutation_rows(self) -> None:
        for row in _retained_record_rows(self):
            with self.subTest(original=row.original, **row.subtest):
                self.positive()
                if row.mutate is not None:
                    row.mutate(self)
                result = self.negative(row.status, row.code, deny=row.deny)
                if row.expected_count is not None:
                    self.assertEqual(result["installed_file_count"], row.expected_count)
                if row.legacy_version is not None:
                    legacy = fixture.checker.read_install_record(self.install.target)
                    self.assertTrue(legacy["readable"])
                    self.assertEqual(legacy["version"], row.legacy_version)

        # These representation refusals are public CLI contracts. The probe's
        # generic child-health check alone cannot witness an escaping TypeError
        # or AttributeError meaningfully.
        for representation in ("nonstring-hash", "nonobject-record"):
            with self.subTest(public_cli_representation=representation):
                self.positive()
                if representation == "nonstring-hash":
                    for side in ("source", "installed"):
                        self.edit_record((side + "_content_sha256",), False)
                else:
                    (self.install.target / fixture.checker.INSTALL_MANIFEST_NAME).write_text("[]\n")
                self.assert_record_cli(2, "record-unverifiable", "invalid-record")


    def test_record_source_path_is_inert_and_incompatible_flags_refuse(self) -> None:
        self.positive()
        self.edit_record(("source_dir",), str(self.retired / "scripts/never-import.py"))
        report = self.probe("--source-dir", str(self.retired))
        self.assertEqual(report["exit"], 0, report)
        self.assertEqual(json.loads(report["stdout"])["status"], "record-consistent")
        for flag in ("--write-manifest", "--list-entries", "--list-files", "--list-directories"):
            with self.subTest(flag=flag):
                self.positive()
                report = self.probe(flag)
                self.assertEqual(report["exit"], 2, report)
                self.assertEqual(report["stdout"], "")
                self.assertIn("--record-check cannot be combined", report["stderr"])


if __name__ == "__main__":
    unittest.main()
