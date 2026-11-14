from __future__ import annotations

import dataclasses
import copy
import errno
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cwo_core.workspace as workspace  # noqa: E402
import cwo_core.workspace_capture as workspace_capture  # noqa: E402
from cwo_core.checked_command import _path_allowed as checked_path_allowed  # noqa: E402
from cwo_core.path_contract import path_components, path_within  # noqa: E402
from cwo_core.workspace import (  # noqa: E402
    capture_tracked_workspace_state,
    capture_workspace_baseline,
    compare_workspace_baseline,
    path_allowed,
)
from cwo_core.workspace_capture import PathReplacedError, read_beneath  # noqa: E402
from tests.real_beads_fixture import configure_git_fixture


# The one reason a non-boolean core.fsmonitor value gives (round 13).
FSMONITOR_REASON = "fsmonitor program configured; dependency coverage cannot be established"
# The reason any other non-empty value gives when the trusted Git is 2.35 (round 14).
FSMONITOR_VERSION_REASON = "fsmonitor value is resolved as a program by this Git version; dependency coverage cannot be established"


def trusted_git_version() -> tuple[int, ...]:
    executable = workspace_capture.trusted_git()
    assert executable is not None, "the tests need a qualified trusted Git"
    return executable.version


def booleans_name_programs(version: tuple[int, ...] | None = None) -> bool:
    """Git 2.35 resolves every non-empty core.fsmonitor value as a program; 2.36 added boolean parsing."""
    return (version or trusted_git_version())[:2] < (2, 36)


def reporting_git_version(version: tuple[int, ...]) -> object:
    """Capture with the real trusted Git, taken to be ``version`` (to apply that release's fsmonitor semantics)."""
    real = workspace_capture.trusted_git()
    assert real is not None
    return mock.patch.object(workspace_capture, "trusted_git", lambda *args, **kwargs: dataclasses.replace(real, version=version))


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def make_repo(base: Path) -> Path:
    repo = base / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    configure_git_fixture(repo)
    git(repo, "config", "user.email", "t@example.invalid")
    git(repo, "config", "user.name", "t")
    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("print('a')\n", encoding="utf-8")
    (repo / "docs").mkdir()
    (repo / "docs" / "guide.md").write_text("guide\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "init")
    return repo


class PathContractTests(unittest.TestCase):
    def test_component_contract(self) -> None:
        allowed = ["github", "src", "docs/", "..cache"]
        cases = {
            ".github/workflows/ci.yml": False,
            "github/workflows/ci.yml": True,
            "srcx/file.py": False,
            "src/app.py": True,
            "./src/app.py": True,
            "src//app.py": True,
            "docs/../sensitive.txt": False,
            "../outside": False,
            "/etc/passwd": False,
            "..cache/x": True,
            "": False,
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(path_allowed(path, allowed), expected)
                self.assertEqual(checked_path_allowed(path, allowed), expected)

    def test_exact_names_are_preserved(self) -> None:
        self.assertEqual(path_components(" spaced name /a -> b"), (" spaced name ", "a -> b"))
        self.assertEqual(path_components('"quoted"'), ('"quoted"',))
        self.assertTrue(path_within("dir/a -> b", ["dir/a -> b"]))
        self.assertFalse(path_within("dir/a", ["dir/a -> b"]))

    def test_invalid_allowed_roots_allow_nothing(self) -> None:
        # "." allowed nothing before this contract too; whole-tree scope is not a root.
        for root in ("", ".", "./", "/", "..", "../x", "/abs", "a\x00b"):
            with self.subTest(root=root):
                self.assertFalse(path_within("a/b", [root]))


class InertInspectionTests(unittest.TestCase):
    def plant(self, repo: Path, base: Path, kind: str) -> Path:
        """Plant one hostile repository command; setup's own git calls cannot trigger it."""
        marker = base / f"{kind.upper()}_RAN"
        if kind != "fsmonitor":
            (repo / ".gitattributes").write_text("*.py filter=evil\n", encoding="utf-8")
            git(repo, "add", ".gitattributes")
            git(repo, "commit", "-qm", "attrs")
        if kind == "fsmonitor":
            git(repo, "config", "core.fsmonitor", f"sh -c 'touch {marker}; exit 1' --")
        elif kind == "clean":
            git(repo, "config", "filter.evil.clean", f"sh -c 'touch {marker}; cat'")
        else:  # long-running process filter
            git(repo, "config", "filter.evil.process", f"sh -c 'touch {marker}; exit 1'")
        marker.unlink(missing_ok=True)
        return marker

    def test_capture_runs_no_repository_configured_code(self) -> None:
        for kind in ("fsmonitor", "clean", "process"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmpdir:
                base = Path(tmpdir)
                repo = make_repo(base)
                marker = self.plant(repo, base, kind)
                # A same-size edit and an mtime-only touch of a filtered file:
                # the cases where git status consults filters.
                (repo / "src" / "app.py").write_text("print('b')\n", encoding="utf-8")
                (repo / "src" / "same.py").write_text("x = 1\n", encoding="utf-8")
                if kind != "fsmonitor":
                    git(repo, "-c", f"filter.evil.{kind}=cat", "add", "src/same.py")
                    git(repo, "-c", f"filter.evil.{kind}=cat", "commit", "-qm", "same")
                later = time.time() + 5
                os.utime(repo / "src" / "same.py", (later, later))
                index = repo / ".git" / "index"
                index_before = (index.read_bytes(), index.stat().st_mtime_ns)
                capture_tracked_workspace_state(repo, include_untracked=True)
                before = capture_workspace_baseline(repo, allowed_paths=["src"])
                after = capture_workspace_baseline(repo, allowed_paths=["src"])
                compare_workspace_baseline(before, after, allowed_paths=["src"])
                self.assertFalse(marker.exists(), f"{kind} must not run")
                self.assertEqual((index.read_bytes(), index.stat().st_mtime_ns), index_before, "the index is not rewritten")
                # Control for this marker alone: ordinary git status runs it.
                subprocess.run(["git", "-C", str(repo), "status", "--porcelain"], check=False, capture_output=True)
                self.assertTrue(marker.exists(), f"control: git status runs the planted {kind}")
                self.assertIn(" M src/app.py", before["tracked_status"])

    def test_git_metadata_tampering_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            hook = repo / ".git" / "hooks" / "pre-commit"
            hook.write_text("#!/bin/sh\necho planted\n", encoding="utf-8")
            hook.chmod(0o755)
            git(repo, "config", "core.sshCommand", "planted")
            after = capture_workspace_baseline(repo, allowed_paths=["src"])
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
        changed = {change["path"] for change in report["git_metadata_changes"]}
        self.assertIn(".git:common:hooks/pre-commit", changed)
        self.assertIn(".git:common:config", changed)
        self.assertTrue(report["unexpected_mutation_detected"])
        self.assertEqual(sorted(report["mutation_categories"]["git-metadata"]), sorted(changed))

    def test_staged_change_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            (repo / "docs" / "guide.md").write_text("edited\n", encoding="utf-8")
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            git(repo, "add", "docs/guide.md")
            after = capture_workspace_baseline(repo, allowed_paths=["src"])
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
        self.assertIn("docs/guide.md", report["mutation_categories"]["out-of-scope"])
        self.assertTrue(report["unexpected_mutation_detected"])

        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            self.assertFalse(before["preexisting_dirty_paths"])
            original = (repo / "src/app.py").read_bytes()
            staged = subprocess.run(
                ["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
                input=b"print('staged-only')\n", capture_output=True, check=True,
            ).stdout.decode().strip()
            git(repo, "update-index", "--cacheinfo", f"100644,{staged},src/app.py")
            after = capture_workspace_baseline(repo, allowed_paths=["src"])
            self.assertEqual((repo / "src/app.py").read_bytes(), original)
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
            changed = next(row for row in report["mutations"] if row["path"] == "src/app.py")
            self.assertFalse(changed["content_changed"])
            self.assertEqual(changed["category"], "scoped")
            self.assertEqual(report["mutation_categories"]["scoped"], ["src/app.py"])
            self.assertNotIn("src/app.py", report["unchanged_dirty"])

    def test_symlinks_are_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            outside = base / "outside.txt"
            outside.write_text("v1\n", encoding="utf-8")
            (repo / "link").symlink_to(outside)
            git(repo, "add", "link")
            git(repo, "commit", "-qm", "link")
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            outside.write_text("v2 changed outside the repository\n", encoding="utf-8")
            middle = capture_workspace_baseline(repo, allowed_paths=["src"])
            (repo / "link").unlink()
            (repo / "link").symlink_to(base / "elsewhere.txt")
            after = capture_workspace_baseline(repo, allowed_paths=["src"])
            unchanged = compare_workspace_baseline(before, middle, allowed_paths=["src"])
            retargeted = compare_workspace_baseline(middle, after, allowed_paths=["src"])
        self.assertFalse(unchanged["mutation_detected"])
        self.assertIn("link", retargeted["mutation_categories"]["out-of-scope"])

    def test_unusual_filenames_are_reported_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            odd = ["a -> b.txt", " spaced .txt", '"quoted".txt', "new\nline.txt", "tab\there.txt"]
            for name in odd:
                (repo / name).write_text("x\n", encoding="utf-8")
            git(repo, "add", "-A")
            git(repo, "commit", "-qm", "odd")
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            for name in odd:
                (repo / name).write_text("changed\n", encoding="utf-8")
            after = capture_workspace_baseline(repo, allowed_paths=["src"])
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
        self.assertEqual(sorted(report["mutation_categories"]["out-of-scope"]), sorted(odd))

    def test_capped_capture_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            evidence = capture_workspace_baseline(repo, allowed_paths=["src", "docs"], max_bytes=4)
        self.assertTrue(evidence["incomplete"])
        self.assertFalse(evidence["baseline_complete"])

    def test_linked_worktree_binds_common_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            worktree = base / "wt"
            git(repo, "worktree", "add", "-q", str(worktree))
            before = capture_workspace_baseline(worktree, allowed_paths=["src"])
            git(repo, "config", "core.sshCommand", "planted")
            after = capture_workspace_baseline(worktree, allowed_paths=["src"])
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
        self.assertNotEqual(before["git_metadata"]["git_dir"], before["git_metadata"]["common_dir"])
        self.assertIn(".git:common:config", {c["path"] for c in report["git_metadata_changes"]})

    def test_clean_repository_round_trips_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            (repo / "src" / "app.py").write_text("print('authorized')\n", encoding="utf-8")
            after = capture_workspace_baseline(repo, allowed_paths=["src"])
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
        self.assertTrue(before["baseline_complete"])
        self.assertEqual(report["mutation_categories"]["scoped"], ["src/app.py"])
        self.assertFalse(report["unexpected_mutation_detected"])


class DescriptorReadTests(unittest.TestCase):
    def test_symlinked_ancestor_is_never_followed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            outside = base / "outside"
            outside.mkdir()
            (outside / "app.py").write_text("print('a')\n", encoding="utf-8")  # same bytes as the tracked file
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            (repo / "src" / "app.py").unlink()
            (repo / "src").rmdir()
            (repo / "src").symlink_to(outside, target_is_directory=True)
            after = capture_workspace_baseline(repo, allowed_paths=["src"])
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
        self.assertIn(" D src/app.py", after["tracked_status"])
        self.assertIn("?? src", after["tracked_status"])
        # The tracked file is absent beneath the root; the outside copy is never read.
        self.assertTrue(after["content_fingerprints"]["src/app.py"].get("absent"))
        self.assertNotIn("src/app.py", after["raw_inventory"])
        self.assertTrue(after["raw_inventory"]["src"].startswith("symlink:"))
        self.assertTrue(report["mutation_detected"])

    def test_special_files_are_not_opened(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            (repo / "docs" / "guide.md").unlink()
            os.mkfifo(repo / "docs" / "guide.md")  # a tracked path replaced by a FIFO
            started = time.monotonic()
            evidence = capture_workspace_baseline(repo, allowed_paths=["src"], include_untracked=True)
            self.assertLess(time.monotonic() - started, 20)
        self.assertIn(" T docs/guide.md", evidence["tracked_status"])
        self.assertEqual(evidence["content_fingerprints"]["docs/guide.md"].get("error"), "unsupported-file-type")
        self.assertTrue(evidence["incomplete"])

    def test_replacement_between_lstat_and_open_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            (base / "regular").write_text("x\n", encoding="utf-8")
            os.mkfifo(base / "pipe")
            real_stat = os.stat
            regular = real_stat(base / "regular", follow_symlinks=False)

            def stale_stat(path, *args, **kwargs):
                # lstat saw a regular file; by open time the name is a FIFO.
                return regular if path == "pipe" else real_stat(path, *args, **kwargs)

            root_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(workspace_capture.os, "stat", side_effect=stale_stat):
                    started = time.monotonic()
                    with self.assertRaises(PathReplacedError):
                        read_beneath(root_fd, "pipe", 1024)
                    self.assertLess(time.monotonic() - started, 5, "a FIFO must not block the read")
            finally:
                os.close(root_fd)


class IndexStateTests(unittest.TestCase):
    def test_skip_worktree_absence_is_intentional(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            git(repo, "update-index", "--skip-worktree", "docs/guide.md")
            (repo / "docs" / "guide.md").unlink()
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            (repo / "docs" / "guide.md").write_text("materialized\n", encoding="utf-8")
            after = capture_workspace_baseline(repo, allowed_paths=["src"])
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
        self.assertNotIn(" D docs/guide.md", before["tracked_status"])
        self.assertTrue(before["baseline_complete"])
        self.assertIn(["100644", mock.ANY, 0, "docs/guide.md", "S"], before["index_entries"])
        self.assertIn("docs/guide.md", report["mutation_categories"]["out-of-scope"])

    def test_sparse_index_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            git(repo, "sparse-checkout", "set", "--cone", "--sparse-index", "src")
            evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
        self.assertEqual(evidence["sparse_directories"], ["docs/"])
        self.assertTrue(evidence["incomplete"])

    def test_conflict_stages_stay_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            git(repo, "checkout", "-qb", "side")
            (repo / "src" / "app.py").write_text("print('side')\n", encoding="utf-8")
            git(repo, "commit", "-qam", "side")
            git(repo, "checkout", "-q", "-")
            (repo / "src" / "app.py").write_text("print('main')\n", encoding="utf-8")
            git(repo, "commit", "-qam", "main")
            subprocess.run(["git", "-C", str(repo), "merge", "-q", "side"], capture_output=True)
            evidence = capture_tracked_workspace_state(repo)
        stages = sorted(entry[2] for entry in evidence["index_entries"] if entry[3] == "src/app.py")
        self.assertEqual(stages, [1, 2, 3])
        self.assertIn("UU src/app.py", evidence["tracked_status"])

    def test_staged_addition_and_unstaged_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            (repo / "docs" / "new.md").write_text("new\n", encoding="utf-8")
            git(repo, "add", "docs/new.md")
            (repo / "docs" / "guide.md").unlink()
            after = capture_workspace_baseline(repo, allowed_paths=["src"])
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
        self.assertIn(" D docs/guide.md", after["tracked_status"])
        flagged = {path for name in ("out-of-scope", "untracked", "attribution-ambiguous") for path in report["mutation_categories"][name]}
        self.assertTrue({"docs/new.md", "docs/guide.md"} <= flagged)
        self.assertTrue(report["unexpected_mutation_detected"])

    def test_executable_bit_follows_git(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            app = repo / "src" / "app.py"
            os.chmod(app, 0o654)  # group execute only: Git still stores 100644
            self.assertNotIn(" M src/app.py", capture_tracked_workspace_state(repo)["tracked_status"])
            os.chmod(app, 0o744)
            self.assertIn(" M src/app.py", capture_tracked_workspace_state(repo)["tracked_status"])

    def test_sha256_repository_is_clean(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "repo"
            subprocess.run(["git", "init", "-q", "--object-format=sha256", str(repo)], check=True)
            configure_git_fixture(repo)
            git(repo, "config", "user.email", "t@example.invalid")
            git(repo, "config", "user.name", "t")
            (repo / "file.txt").write_text("content\n", encoding="utf-8")
            (repo / "link").symlink_to("file.txt")
            git(repo, "add", "-A")
            git(repo, "commit", "-qm", "init")
            evidence = capture_workspace_baseline(repo, allowed_paths=["file.txt"])
        self.assertEqual(evidence["object_format"], "sha256")
        self.assertEqual(evidence["tracked_status"], [])
        self.assertTrue(evidence["baseline_complete"])

    def test_conversion_is_baseline_dirt_not_a_new_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            (repo / ".gitattributes").write_text("*.txt ident\n", encoding="utf-8")
            (repo / "id.txt").write_text("$Id$\n", encoding="utf-8")
            git(repo, "add", "-A")
            git(repo, "commit", "-qm", "ident")
            (repo / "id.txt").unlink()
            git(repo, "checkout", "--", "id.txt")  # the smudged copy differs from the stored blob
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            again = capture_workspace_baseline(repo, allowed_paths=["src"])
            unchanged = compare_workspace_baseline(before, again, allowed_paths=["src"])
            (repo / "src" / "app.py").write_text("print('edit')\n", encoding="utf-8")
            edited = compare_workspace_baseline(before, capture_workspace_baseline(repo, allowed_paths=["src"]), allowed_paths=["src"])
        self.assertIn(" M id.txt", before["preexisting_dirty_paths"] and before["tracked_status"])
        self.assertIn(".gitattributes", before["normalization_sources"])
        self.assertFalse(unchanged["mutation_detected"])
        self.assertEqual(edited["mutation_categories"]["scoped"], ["src/app.py"])
        self.assertFalse(edited["unexpected_mutation_detected"])

    def test_subdirectory_root_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            evidence = capture_workspace_baseline(repo / "src", allowed_paths=["app.py"])
        self.assertTrue(evidence["incomplete"])
        self.assertFalse(evidence["baseline_complete"])

    def test_missing_object_with_promisor_runs_no_helper(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            (repo / ".gitattributes").write_text("*.txt text\n", encoding="utf-8")
            git(repo, "add", ".gitattributes")
            git(repo, "commit", "-qm", "attrs")
            oid = subprocess.run(["git", "-C", str(repo), "rev-parse", ":.gitattributes"], check=True, capture_output=True, text=True).stdout.strip()
            (repo / ".git" / "objects" / oid[:2] / oid[2:]).unlink()
            marker = base / "PROMISOR_RAN"
            git(repo, "config", "extensions.partialClone", "origin")
            git(repo, "config", "remote.origin.promisor", "true")
            git(repo, "config", "remote.origin.url", str(base / "upstream"))
            git(repo, "config", "remote.origin.uploadpack", f"sh -c 'touch {marker}; exit 1' --")
            (repo / ".gitattributes").unlink()
            capture_tracked_workspace_state(repo, include_untracked=True)
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            compare_workspace_baseline(before, capture_workspace_baseline(repo, allowed_paths=["src"]), allowed_paths=["src"])
            self.assertFalse(marker.exists(), "inspection must not invoke the promisor helper")
            # Control: attribute lookup does invoke it, and still exits zero.
            control = subprocess.run(["git", "-C", str(repo), "check-attr", "-a", "src/app.py"], capture_output=True)
            self.assertEqual(control.returncode, 0)
            self.assertTrue(marker.exists(), "control: check-attr runs the helper")


class MetadataScopeTests(unittest.TestCase):
    def changes(self, repo: Path, mutate, root: Path | None = None) -> dict[str, str]:
        target = root or repo
        before = capture_workspace_baseline(target, allowed_paths=["src"])
        mutate()
        after = capture_workspace_baseline(target, allowed_paths=["src"])
        report = compare_workspace_baseline(before, after, allowed_paths=["src"])
        self.assertTrue(report["unexpected_mutation_detected"])
        return {change["path"]: change["category"] for change in report["git_metadata_changes"]}

    def test_alternates_nested_hooks_and_refs_are_classified(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            git_dir = repo / ".git"

            def alternates() -> None:
                (git_dir / "objects" / "info").mkdir(parents=True, exist_ok=True)
                (git_dir / "objects" / "info" / "alternates").write_text("/elsewhere/objects\n", encoding="utf-8")

            def nested_hook() -> None:
                (git_dir / "hooks" / "pre-commit.d").mkdir()
                (git_dir / "hooks" / "pre-commit.d" / "run").write_text("#!/bin/sh\n", encoding="utf-8")

            def new_ref() -> None:
                git(repo, "branch", "planted")

            # Planting an alternate store makes the later capture unsupported, so
            # the comparison cannot be complete.
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            alternates()
            after = capture_workspace_baseline(repo, allowed_paths=["src"])
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
            self.assertTrue(after["incomplete"])
            self.assertIn("alternate object stores are not supported", " ".join(after["incomplete_reasons"]))
            self.assertTrue(report["unexpected_mutation_detected"])
            (git_dir / "objects" / "info" / "alternates").unlink()
            nested = self.changes(repo, nested_hook)
            self.assertEqual(nested.get(".git:common:hooks/pre-commit.d/run"), "git-metadata")
            refs = self.changes(repo, new_ref)
            self.assertTrue(refs)
            self.assertEqual(set(refs.values()), {"git-refs"})

    def test_within_capture_indirection_retarget_is_incomplete(self) -> None:
        # Real linked-worktree layouts and real file rewrites, at two deterministic
        # capture boundaries; no scheduler race or invented capture error.
        for kind in ("gitdir", "commondir"):
            for phase in ("_preflight", "_conversions"):
                with self.subTest(kind=kind, phase=phase), tempfile.TemporaryDirectory() as tmpdir:
                    base = Path(tmpdir)
                    repo = make_repo(base)
                    worktree = base / "wt"
                    git(repo, "worktree", "add", "-q", str(worktree))
                    _, git_dir, common_dir = workspace_capture.repository_dirs(worktree)
                    alternate = base / "alternate"
                    shutil.copytree(git_dir if kind == "gitdir" else common_dir, alternate)
                    if kind == "gitdir":
                        (alternate / "commondir").write_text(common_dir + "\n", encoding="utf-8")
                    indirection = worktree / ".git" if kind == "gitdir" else Path(git_dir) / "commondir"
                    before = capture_workspace_baseline(worktree, allowed_paths=["src"])
                    unchanged = capture_workspace_baseline(worktree, allowed_paths=["src"])
                    self.assertTrue(before["baseline_complete"], before["incomplete_reasons"])
                    self.assertTrue(unchanged["baseline_complete"], unchanged["incomplete_reasons"])
                    self.assertFalse(compare_workspace_baseline(before, unchanged, allowed_paths=["src"])["unexpected_mutation_detected"])
                    real = getattr(workspace_capture.WorktreeCapture, phase)
                    rewrites = []

                    def retarget(capture):
                        result = real(capture)
                        if capture.root == worktree:
                            indirection.write_text(("gitdir: " if kind == "gitdir" else "") + str(alternate) + "\n", encoding="utf-8")
                            rewrites.append(indirection)
                        return result

                    with mock.patch.object(workspace_capture.WorktreeCapture, phase, retarget):
                        after = capture_workspace_baseline(worktree, allowed_paths=["src"])
                    self.assertEqual(rewrites, [indirection])
                    self.assertNotEqual(workspace_capture.repository_dirs(worktree)[1:], (git_dir, common_dir))
                    # Both the old and retargeted contexts are supported, complete positives.
                    fresh = capture_workspace_baseline(worktree, allowed_paths=["src"])
                    self.assertTrue(fresh["baseline_complete"], fresh["incomplete_reasons"])
                    self.assertTrue(after["incomplete"], "changed Git indirection must not return a complete capture")
                    reason = "other than the one checked" if phase == "_preflight" else "capture identity changed during capture"
                    self.assertIn(reason, " ".join(after["incomplete_reasons"]))
                    self.assertTrue(compare_workspace_baseline(before, after, allowed_paths=["src"])["unexpected_mutation_detected"])

    def test_worktree_indirection_change_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            worktree = base / "wt"
            git(repo, "worktree", "add", "-q", str(worktree))
            gitfile = worktree / ".git"
            original = gitfile.read_text(encoding="utf-8")

            def touch_gitfile() -> None:
                gitfile.write_text(original + "\n", encoding="utf-8")

            changed = self.changes(repo, touch_gitfile, root=worktree)
        self.assertEqual(changed.get(".git:worktree:.git"), "git-metadata")


TRANSITION_BINDING_FIELDS = (
    "capture_identity", "git_executable", "object_format", "head", "head_manifest_sha256", "git_metadata",
)


def expected_transition_record(before, after, paths=None):
    """A trusted caller's explicit approval fixture, never capture-derived authority."""
    changes = compare_workspace_baseline(before, after)["git_metadata_changes"]
    return {
        "record_type": "expected-git-transition", "version": 1,
        "approved": True, "reason": "Approved test transition",
        "before": {key: copy.deepcopy(before[key]) for key in TRANSITION_BINDING_FIELDS},
        "after": {key: copy.deepcopy(after[key]) for key in TRANSITION_BINDING_FIELDS},
        "paths": [change["path"] for change in changes] if paths is None else paths,
    }


class ExpectedGitTransitionTests(unittest.TestCase):
    def indirection_transition(self, base):
        repo = make_repo(base)
        worktree = base / "wt"
        git(repo, "worktree", "add", "-q", str(worktree))
        before = capture_workspace_baseline(worktree, allowed_paths=["src"])
        git_dir = Path(before["git_metadata"]["git_dir"])
        replacement = base / "approved-gitdir"
        shutil.copytree(git_dir, replacement)
        (replacement / "commondir").write_text(before["git_metadata"]["common_dir"] + "\n", encoding="utf-8")
        (worktree / ".git").write_text(f"gitdir: {replacement}\n", encoding="utf-8")
        after = capture_workspace_baseline(worktree, allowed_paths=["src"])
        self.assertTrue(before["baseline_complete"], before["incomplete_reasons"])
        self.assertTrue(after["baseline_complete"], after["incomplete_reasons"])
        return worktree, before, after

    def test_authorized_indirection_passes_only_with_explicit_record(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, before, after = self.indirection_transition(Path(tmpdir))
            record = expected_transition_record(before, after)
            self.assertTrue(compare_workspace_baseline(before, after)["unexpected_mutation_detected"])
            after["expected_git_transition"] = record
            self.assertTrue(compare_workspace_baseline(before, after)["unexpected_mutation_detected"])
            report = compare_workspace_baseline(before, after, expected_git_transition=record)
        self.assertFalse(report["unexpected_mutation_detected"], report["unexpected_mutations"])
        self.assertTrue(report["mutation_detected"])
        self.assertEqual(report["expected_git_transition"]["status"], "accepted")
        self.assertTrue(all(change["authorization"] == "authorized" for change in report["git_metadata_changes"]))
        self.assertIn(".git:capture-identity", [change["path"] for change in report["git_metadata_changes"]])

    def test_records_refuse_malformed_unapproved_and_stale_bindings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, before, after = self.indirection_transition(Path(tmpdir))
            original = expected_transition_record(before, after)
            cases = {
                "not an object": [], "unapproved": {**original, "approved": False},
                "numeric approval": {**original, "approved": 1},
                "unknown version": {**original, "version": 2},
                "numeric version": {**original, "version": True},
                "missing reason": {**original, "reason": " "},
                "wildcard": {**original, "paths": [".git:*"]},
                "duplicate": {**original, "paths": original["paths"] * 2},
                "unchanged path": {**original, "paths": [".git:common:config"]},
                "empty": {**original, "paths": []},
                "extra field": {**original, "allow_all": True},
            }
            stale = copy.deepcopy(original)
            stale["before"]["git_metadata"]["entries"]["common:config"]["sha256"] = "0" * 64
            cases["stale before"] = stale
            stale = copy.deepcopy(original)
            stale["after"]["capture_identity"]["git_dir"][1] += 1
            cases["stale after identity"] = stale
            for name, record in cases.items():
                with self.subTest(name=name):
                    report = compare_workspace_baseline(before, after, expected_git_transition=record)
                    self.assertTrue(report["unexpected_mutation_detected"])
                    self.assertEqual(report["expected_git_transition"]["status"], "refused")
                    self.assertFalse(any(c["authorization"] == "authorized" for c in report["git_metadata_changes"]))

    def test_selected_changes_do_not_approve_other_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, before, after = self.indirection_transition(Path(tmpdir))
            record = expected_transition_record(before, after, [".git:worktree:.git"])
            report = compare_workspace_baseline(before, after, expected_git_transition=record)
        statuses = {change["path"]: change["authorization"] for change in report["git_metadata_changes"]}
        self.assertEqual(statuses[".git:worktree:.git"], "authorized")
        self.assertEqual(statuses[".git:capture-identity"], "unexplained")
        self.assertTrue(report["unexpected_mutation_detected"])

    def test_record_cannot_authorize_incomplete_legacy_or_replaced_root(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, before, after = self.indirection_transition(Path(tmpdir))
            for kind in ("incomplete", "legacy", "missing identity", "missing metadata", "root replacement"):
                candidate = copy.deepcopy(after)
                if kind == "incomplete":
                    candidate["incomplete"] = True
                elif kind == "legacy":
                    candidate["evidence_version"] = 2
                elif kind == "missing identity":
                    del candidate["capture_identity"]
                elif kind == "missing metadata":
                    del candidate["git_metadata"]
                else:
                    candidate["capture_identity"]["root"][1] += 1
                record = expected_transition_record(before, after)
                if kind == "root replacement":
                    record["after"]["capture_identity"] = candidate["capture_identity"]
                with self.subTest(kind=kind):
                    report = compare_workspace_baseline(before, candidate, expected_git_transition=record)
                    self.assertTrue(report["unexpected_mutation_detected"])
                    self.assertEqual(report["expected_git_transition"]["status"], "refused")

    def test_changed_indirection_or_config_invalidates_record(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            worktree, before, approved = self.indirection_transition(Path(tmpdir))
            record = expected_transition_record(before, approved)
            approved_gitfile = (worktree / ".git").read_text(encoding="utf-8")
            for kind in ("indirection", "config"):
                (worktree / ".git").write_text(approved_gitfile, encoding="utf-8")
                if kind == "indirection":
                    with (worktree / ".git").open("a", encoding="utf-8") as handle:
                        handle.write("\n")
                else:
                    git(worktree, "config", "core.sshCommand", "unapproved")
                after = capture_workspace_baseline(worktree, allowed_paths=["src"])
                with self.subTest(kind=kind):
                    report = compare_workspace_baseline(before, after, expected_git_transition=record)
                    self.assertTrue(report["unexpected_mutation_detected"])
                    self.assertEqual(report["expected_git_transition"]["status"], "refused")

    def test_matching_record_cannot_validate_malformed_capture_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, before, after = self.indirection_transition(Path(tmpdir))
            for kind in ("version", "head", "mode", "referent", "entry names", "identity"):
                candidate = copy.deepcopy(after)
                entries = candidate["git_metadata"]["entries"]
                if kind == "version":
                    candidate["evidence_version"] = "bad"
                elif kind == "head":
                    candidate["head"] = "bad"
                elif kind == "mode":
                    entries["common:config"]["mode"] = True
                elif kind == "referent":
                    entries["common:config"] = {"kind": "symlink", "mode": 0o777, "sha256": "0" * 64,
                                                "referent": {"kind": "unreadable"}}
                elif kind == "entry names":
                    entries[4] = {"kind": "absent"}
                else:
                    candidate["capture_identity"]["git_dir"] = [1, True, 0o40755]
                record = expected_transition_record(before, after)
                record["after"] = {key: candidate[key] for key in TRANSITION_BINDING_FIELDS}
                with self.subTest(kind=kind):
                    report = compare_workspace_baseline(before, candidate, expected_git_transition=record)
                    self.assertTrue(report["unexpected_mutation_detected"])
                    self.assertEqual(report["expected_git_transition"]["status"], "refused")


def make_dirty_repo(base: Path) -> Path:
    repo = make_repo(base)
    (repo / "docs" / "guide.md").write_text("dirty\n", encoding="utf-8")
    return repo


class FailClosedTests(unittest.TestCase):
    def test_failed_captures_never_compare_clean(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            plain = Path(tmpdir) / "plain"
            plain.mkdir()
            before = capture_workspace_baseline(plain, allowed_paths=["x"])
            after = capture_workspace_baseline(plain, allowed_paths=["x"])
            report = compare_workspace_baseline(before, after, allowed_paths=["x"])
            state_before = capture_tracked_workspace_state(plain)
            legacy = workspace.diff_workspace_state(
                {k: v for k, v in state_before.items() if k != "content_fingerprints"},
                {k: v for k, v in capture_tracked_workspace_state(plain).items() if k != "content_fingerprints"},
            )
        self.assertTrue(before["incomplete"] and not before["baseline_complete"])
        self.assertTrue(report["incomplete"] and report["unexpected_mutation_detected"] and report["capture_failed"])
        self.assertTrue(legacy["incomplete"] and legacy["unexpected_mutation_detected"])

    def test_every_cap_makes_the_capture_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            (repo / "link").symlink_to("x" * 200)
            cases = {
                "files": capture_workspace_baseline(repo, allowed_paths=["src"], max_files=1),
                "bytes": capture_workspace_baseline(repo, allowed_paths=["src"], max_bytes=4),
                "time": capture_workspace_baseline(repo, allowed_paths=["src"], max_seconds=0),
            }
            with mock.patch.object(workspace, "_entries_cap", return_value=2):
                cases["entries"] = capture_workspace_baseline(repo, allowed_paths=["src"])
        for name, evidence in cases.items():
            with self.subTest(cap=name):
                self.assertTrue(evidence["incomplete"])
                self.assertFalse(evidence["baseline_complete"])
                self.assertIn("budget", evidence["error_kind"])

    def test_symlink_targets_count_against_the_byte_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            (repo / "link").symlink_to("y" * 3000)
            evidence = capture_workspace_baseline(repo, allowed_paths=["src"], max_bytes=2048)
        self.assertTrue(evidence["incomplete"])


class StagedStateTests(unittest.TestCase):
    def test_staged_changes_are_dirt_against_head(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            (repo / "docs" / "guide.md").write_text("staged\n", encoding="utf-8")
            (repo / "new.txt").write_text("added\n", encoding="utf-8")
            git(repo, "add", "docs/guide.md", "new.txt")
            git(repo, "rm", "-q", "src/app.py")
            state = capture_tracked_workspace_state(repo)
            before = {k: v for k, v in state.items() if k != "content_fingerprints"}
            strict = workspace.diff_workspace_state(before, before, require_clean=True)
            clean = workspace.workspace_is_clean(repo, include_untracked=False)
        self.assertIn("M  docs/guide.md", state["tracked_status"])
        self.assertIn("A  new.txt", state["tracked_status"])
        self.assertIn("D  src/app.py", state["tracked_status"])
        self.assertTrue(strict["unexpected_mutation_detected"])
        self.assertFalse(clean)

    def test_unborn_branch_reports_additions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "repo"
            repo.mkdir()
            git(repo, "init", "-q")
            configure_git_fixture(repo)
            (repo / "a.txt").write_text("a\n", encoding="utf-8")
            git(repo, "add", "a.txt")
            state = capture_tracked_workspace_state(repo)
        self.assertEqual(state["head"], "unborn")
        self.assertEqual(state["tracked_status"], ["A  a.txt"])


class RawInventoryTests(unittest.TestCase):
    def test_mode_change_on_a_dirty_file_is_a_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_dirty_repo(Path(tmpdir))
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            os.chmod(repo / "docs" / "guide.md", 0o600)
            after = capture_workspace_baseline(repo, allowed_paths=["src"])
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
        self.assertEqual(before["tracked_status"], after["tracked_status"])
        self.assertIn("docs/guide.md", report["mutation_categories"]["out-of-scope"])

    def test_materialized_skip_worktree_file_with_index_bytes_is_a_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            git(repo, "update-index", "--skip-worktree", "docs/guide.md")
            original = (repo / "docs" / "guide.md").read_text(encoding="utf-8")
            (repo / "docs" / "guide.md").unlink()
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            (repo / "docs" / "guide.md").write_text(original, encoding="utf-8")
            after = capture_workspace_baseline(repo, allowed_paths=["src"])
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
        self.assertTrue(report["unexpected_mutation_detected"])
        self.assertIn("docs/guide.md", report["mutation_categories"]["out-of-scope"])

    def test_special_entries_and_dangling_links_in_declared_paths_are_inventoried(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            os.mkfifo(repo / "src" / "pipe")
            (repo / "src" / "dangling").symlink_to("missing-target")
            sock = socket.socket(socket.AF_UNIX)
            try:
                sock.bind(str(repo / "src" / "sock"))
                after = capture_workspace_baseline(repo, allowed_paths=["src"])
            finally:
                sock.close()
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
        for name in ("src/pipe", "src/dangling", "src/sock"):
            with self.subTest(name=name):
                self.assertIn(name, after["raw_inventory"])
                self.assertIn(name, {m["path"] for m in report["mutations"]})

    @unittest.skipIf(os.geteuid() == 0, "root reads mode-000 directories")
    def test_unreadable_directory_makes_the_capture_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            locked = repo / "locked"
            locked.mkdir()
            (locked / "secret.txt").write_text("x\n", encoding="utf-8")
            locked.chmod(0)
            try:
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
            finally:
                locked.chmod(0o700)
        self.assertTrue(evidence["incomplete"])
        self.assertTrue(any("locked" in reason for reason in evidence["incomplete_reasons"]))

    def test_new_ignored_tree_hidden_by_its_own_gitignore_is_seen(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            (repo / "stash").mkdir()
            (repo / "stash" / ".gitignore").write_text("*\n", encoding="utf-8")
            (repo / "stash" / "payload.py").write_text("x\n", encoding="utf-8")
            after = capture_workspace_baseline(repo, allowed_paths=["src"])
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
        changed = {m["path"] for m in report["unexpected_mutations"]}
        self.assertTrue({"stash/.gitignore", "stash/payload.py"} <= changed)


class MetadataDependencyTests(unittest.TestCase):
    def report_for(self, repo: Path, mutate) -> dict:
        before = capture_workspace_baseline(repo, allowed_paths=["src"])
        mutate()
        after = capture_workspace_baseline(repo, allowed_paths=["src"])
        return compare_workspace_baseline(before, after, allowed_paths=["src"])

    def test_config_dependencies_are_snapshotted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            hooks = repo / "src" / "hooks"
            hooks.mkdir()
            (hooks / "pre-commit").write_text("#!/bin/sh\n", encoding="utf-8")
            git(repo, "config", "core.hooksPath", "src/hooks")
            report = self.report_for(repo, lambda: (hooks / "pre-commit").write_text("#!/bin/sh\necho planted\n", encoding="utf-8"))
            categories = {change["path"]: change["category"] for change in report["git_metadata_changes"]}
            self.assertTrue(any("hookspath" in path.lower() for path in categories), categories)
            self.assertTrue(report["unexpected_mutation_detected"])
            # The hooks directory sits inside the allowed path, yet its change
            # is still reported as Git metadata.
            self.assertIn("git-metadata", set(categories.values()))

    def test_config_naming_more_files_is_unsupported(self) -> None:
        cases = {
            "include": ("include.path", "../included.cfg"),
            "conditional include": ("includeIf.gitdir:/.path", "../included.cfg"),
            "excludes file": ("core.excludesFile", ".git/custom-excludes"),
            "attributes file": ("core.attributesFile", ".git/custom-attributes"),
            "split index": ("core.splitIndex", "true"),
        }
        for label, (key, value) in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                git(repo, "config", key, value)
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertTrue(evidence["incomplete"])
                self.assertIn("unsupported repository configuration", " ".join(evidence["incomplete_reasons"]))
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            # A mention in a comment is enough: no config syntax is interpreted.
            with open(repo / ".git" / "config", "a", encoding="utf-8") as stream:
                stream.write("# [include] path = elsewhere\n")
            self.assertTrue(capture_workspace_baseline(repo, allowed_paths=["src"])["incomplete"])

    def test_symlinked_hook_referent_change_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            target = base / "real-hook"
            target.write_text("#!/bin/sh\n", encoding="utf-8")
            (repo / ".git" / "hooks" / "pre-push").symlink_to(target)
            report = self.report_for(repo, lambda: target.write_text("#!/bin/sh\nplanted\n", encoding="utf-8"))
        self.assertIn(".git:common:hooks/pre-push", {c["path"] for c in report["git_metadata_changes"]})

    def test_replaced_worktree_root_changes_capture_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            moved = base / "moved"
            repo.rename(moved)
            subprocess.run(["cp", "-a", str(moved), str(repo)], check=True)
            after = capture_workspace_baseline(repo, allowed_paths=["src"])
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
        self.assertIn(".git:capture-identity", {c["path"] for c in report["git_metadata_changes"]})


class TrustedGitTests(unittest.TestCase):
    def test_only_fixed_trustworthy_paths_are_used(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            fake = base / "git"
            marker = base / "FAKE_GIT_RAN"
            fake.write_text(f"#!/bin/sh\ntouch {marker}\nexec /usr/bin/git \"$@\"\n", encoding="utf-8")
            fake.chmod(0o775)  # group-writable: never trusted
            self.assertIsNone(workspace_capture.trusted_git((str(fake),)))
            repo = make_repo(base)
            with mock.patch.dict(os.environ, {"PATH": f"{base}:{os.environ.get('PATH', '')}"}):
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
            self.assertFalse(marker.exists(), "a git earlier on PATH is never run")
        self.assertTrue(evidence["baseline_complete"])
        self.assertTrue(evidence["git_executable"]["path"].startswith("/"))


class CheckedCommandRootTests(unittest.TestCase):
    def test_raw_roots_must_satisfy_the_contract_before_resolution(self) -> None:
        from cwo_core.checked_command import normalize_command_spec

        with tempfile.TemporaryDirectory() as tmpdir:
            cwd = Path(tmpdir)
            (cwd / "docs").mkdir()
            base = {"spec_type": "cwo-checked-command-spec", "version": 1, "command_id": "c", "mode": "argv",
                    "argv": ["true"], "cwd": str(cwd), "env": {}, "inherit_environment": False, "stdin": None,
                    "source": None, "preflights": [], "mutation_intent": "workspace-scoped", "timeout_seconds": 5}
            for root in ("docs/../sensitive", str(cwd / "docs"), "../outside", "."):
                with self.subTest(root=root), self.assertRaises(ValueError):
                    normalize_command_spec({**base, "allowed_paths": [root]})
            self.assertEqual(normalize_command_spec({**base, "allowed_paths": ["./docs//x"]})["allowed_paths"], ["docs/x"])


class DigestTests(unittest.TestCase):
    def test_worktree_digest_is_inert_and_classifies_non_repositories(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            plain = base / "plain"
            plain.mkdir()
            self.assertEqual(workspace.worktree_state_digest(plain), ("unavailable-not-git", None))
            repo = make_repo(base)
            status, first = workspace.worktree_state_digest(repo / "src")
            (repo / "src" / "app.py").write_text("print('changed')\n", encoding="utf-8")
            _, second = workspace.worktree_state_digest(repo)
        self.assertEqual(status, "available")
        self.assertNotEqual(first, second)


class RoundThreeTests(unittest.TestCase):
    """Trusted discovery, filesystem entry types and bounded metadata reads."""

    def test_other_modules_use_the_trusted_git(self) -> None:
        import cwo_core.native_activation_preview as preview
        import cwo_core.native_live_campaign_contracts as campaign

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            marker = base / "FAKE_GIT_RAN"
            fake = base / "bin" / "git"
            fake.parent.mkdir()
            fake.write_text(f"#!/bin/sh\ntouch {marker}\nexit 0\n", encoding="utf-8")
            fake.chmod(0o755)
            with mock.patch.dict(os.environ, {"PATH": f"{fake.parent}:{os.environ.get('PATH', '')}"}):
                head = preview._git(repo, "rev-parse", "HEAD")
                tree = campaign._run_git(repo, "rev-parse", "HEAD^{tree}")
            self.assertFalse(marker.exists(), "a git earlier on PATH is never run")
        self.assertEqual(len(head), 40)
        self.assertEqual(len(tree), 40)

    def test_calibration_digest_covers_metadata_and_head(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            _, first = workspace.worktree_state_digest(repo)
            git(repo, "config", "core.sshCommand", "planted")
            _, second = workspace.worktree_state_digest(repo)
            git(repo, "commit", "-q", "--allow-empty", "-m", "moves HEAD")
            _, third = workspace.worktree_state_digest(repo)
        self.assertNotEqual(first, second, "a config-only change changes the digest")
        self.assertNotEqual(second, third, "a HEAD-only change changes the digest")

    def test_discovery_failures_are_errors_not_non_repositories(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            with mock.patch.object(workspace_capture, "trusted_git", return_value=None):
                with self.assertRaises(workspace.WorkspaceInspectionError):
                    workspace.worktree_state_digest(repo)
            with mock.patch.object(workspace_capture, "run_git", side_effect=workspace_capture.BudgetExhausted("deadline")):
                with self.assertRaises(workspace.WorkspaceInspectionError):
                    workspace.worktree_state_digest(repo)
            plain = Path(tmpdir) / "plain"
            plain.mkdir()
            self.assertEqual(workspace.worktree_state_digest(plain), ("unavailable-not-git", None))

    def test_directories_and_special_types_are_inventoried(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            os.mkfifo(repo / "src" / "pipe")
            sock = socket.socket(socket.AF_UNIX)
            try:
                sock.bind(str(repo / "src" / "sock"))
                before = capture_workspace_baseline(repo, allowed_paths=["src"])
                os.chmod(repo / "docs", 0o700)
                (repo / "empty").mkdir()
                after = capture_workspace_baseline(repo, allowed_paths=["src"])
            finally:
                sock.close()
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
        self.assertTrue(before["raw_inventory"]["src/pipe"].startswith("fifo:"))
        self.assertTrue(before["raw_inventory"]["src/sock"].startswith("socket:"))
        changed = {m["path"] for m in report["unexpected_mutations"]}
        self.assertTrue({"docs", "empty"} <= changed, changed)

    def test_declared_paths_overlapping_gitlinks_are_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            (base / "subsrc").mkdir()
            sub = make_repo(base / "subsrc")
            git(repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub), "vendor/lib")
            git(repo, "commit", "-qm", "submodule")
            for declared in ("vendor/lib/src", "vendor/lib", "vendor"):
                with self.subTest(declared=declared):
                    self.assertTrue(capture_workspace_baseline(repo, allowed_paths=[declared])["incomplete"])
            plain = capture_workspace_baseline(repo, allowed_paths=["src"])
        self.assertFalse(plain["incomplete"])
        self.assertTrue(plain["raw_inventory"]["vendor/lib"].startswith("gitlink:"))

    def test_excluded_names_on_declared_paths_are_observed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            cache = repo / "src" / "__pycache__"
            cache.mkdir()
            (cache / "app.cpython-314.pyc").write_bytes(b"one")
            (repo / "docs" / "__pycache__").mkdir()
            (repo / "docs" / "__pycache__" / "x.pyc").write_bytes(b"skipped off declared paths")
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            (cache / "app.cpython-314.pyc").write_bytes(b"two")
            after = capture_workspace_baseline(repo, allowed_paths=["src"])
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
            beads = capture_workspace_baseline(repo, allowed_paths=[".beads/state"])
        self.assertIn("src/__pycache__/app.cpython-314.pyc", before["raw_inventory"])
        self.assertNotIn("docs/__pycache__/x.pyc", before["raw_inventory"])
        self.assertIn("src/__pycache__/app.cpython-314.pyc", report["mutation_categories"]["scoped"])
        self.assertFalse(beads["incomplete"])

    def test_ignored_file_content_is_hashed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            (repo / ".gitignore").write_text("build/\n", encoding="utf-8")
            git(repo, "add", ".gitignore")
            git(repo, "commit", "-qm", "ignore")
            (repo / "build").mkdir()
            artifact = repo / "build" / "out.bin"
            artifact.write_bytes(b"AAAA")
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            stamp = artifact.stat()
            artifact.write_bytes(b"BBBB")
            os.utime(artifact, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            after = capture_workspace_baseline(repo, allowed_paths=["src"])
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
        self.assertNotIn("sig-", before["raw_inventory"]["build/out.bin"])
        self.assertIn("build/out.bin", {m["path"] for m in report["unexpected_mutations"]})

    def test_symlinked_hooks_directory_is_traversed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            external = base / "shared-hooks"
            external.mkdir()
            (external / "pre-commit").write_text("#!/bin/sh\n", encoding="utf-8")
            hooks = repo / ".git" / "hooks"
            for item in hooks.iterdir():
                item.unlink()
            hooks.rmdir()
            hooks.symlink_to(external, target_is_directory=True)
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            (external / "pre-commit").write_text("#!/bin/sh\necho planted\n", encoding="utf-8")
            after = capture_workspace_baseline(repo, allowed_paths=["src"])
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
        self.assertIn(".git:common:hooks/pre-commit", {c["path"] for c in report["git_metadata_changes"]})

    @unittest.skipIf(os.geteuid() == 0, "root reads mode-000 directories")
    def test_metadata_read_failures_are_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            info = repo / ".git" / "info"
            info.chmod(0)
            try:
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
            finally:
                info.chmod(0o755)
        self.assertTrue(evidence["incomplete"])
        self.assertTrue(any("info" in reason for reason in evidence["incomplete_reasons"]))

    def test_unreadable_head_is_not_an_unborn_branch(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            branch = subprocess.run(["git", "-C", str(repo), "symbolic-ref", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
            (repo / ".git" / branch).write_text("1" * 40 + "\n", encoding="utf-8")
            evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
        self.assertTrue(evidence["incomplete"])
        self.assertEqual(evidence["error_kind"], "git-failed")

    def test_git_output_and_index_entries_are_budgeted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            git_exe = workspace_capture.trusted_git()
            with self.assertRaises(workspace_capture.BudgetExhausted):
                workspace_capture.run_git(git_exe, repo, ["ls-files", "-s"], max_output=8)
            with mock.patch.object(workspace, "_entries_cap", return_value=1):
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
        self.assertEqual(evidence["error_kind"], "budget")

    def test_fifo_substitution_never_opens_the_fifo_for_reading(self) -> None:
        import threading

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            (base / "regular").write_text("x\n", encoding="utf-8")
            os.mkfifo(base / "pipe")
            regular = os.stat(base / "regular", follow_symlinks=False)
            opened_for_write = threading.Event()

            def writer() -> None:
                fd = os.open(base / "pipe", os.O_WRONLY)  # blocks until a reader opens the FIFO
                opened_for_write.set()
                os.close(fd)

            thread = threading.Thread(target=writer, daemon=True)
            thread.start()
            root_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(PathReplacedError):
                    workspace_capture._read_pinned(root_fd, "pipe", regular, 1024)
                self.assertFalse(opened_for_write.wait(0.5), "the writer must not have been woken")
            finally:
                os.close(root_fd)
                reader = os.open(base / "pipe", os.O_RDONLY | os.O_NONBLOCK)
                thread.join(5)
                os.close(reader)

    def test_new_ancestor_directories_of_declared_paths_are_in_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            before = capture_workspace_baseline(repo, allowed_paths=["out/deep/result.txt"])
            (repo / "out" / "deep").mkdir(parents=True)
            (repo / "out" / "deep" / "result.txt").write_text("ok\n", encoding="utf-8")
            created = compare_workspace_baseline(before, capture_workspace_baseline(repo, allowed_paths=["out/deep/result.txt"]),
                                                 allowed_paths=["out/deep/result.txt"])
            os.chmod(repo / "src", 0o700)  # an existing directory that is not on a declared path
            changed = compare_workspace_baseline(before, capture_workspace_baseline(repo, allowed_paths=["out/deep/result.txt"]),
                                                 allowed_paths=["out/deep/result.txt"])
        self.assertEqual(sorted(created["mutation_categories"]["scoped"]), ["out", "out/deep", "out/deep/result.txt"])
        self.assertFalse(created["unexpected_mutation_detected"])
        self.assertIn("src", changed["mutation_categories"]["out-of-scope"])

    def test_conversion_attributes_make_cleanliness_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            self.assertTrue(workspace.workspace_is_clean(repo, include_untracked=False))
            (repo / ".gitattributes").write_text("*.py filter=lfs\n", encoding="utf-8")
            git(repo, "add", ".gitattributes")
            git(repo, "commit", "-qm", "attrs")
            state = capture_tracked_workspace_state(repo)
            self.assertEqual(state["tracked_status"], [])
            self.assertEqual(state["git_cleanliness"], "unknown-conversions")
            self.assertFalse(workspace.workspace_is_clean(repo, include_untracked=False))


class RoundFourTests(unittest.TestCase):
    """Qualified repository layouts and preflight checks precede Git reads."""

    INSPECTION = {"merge-base", "rev-parse", "show", "ls-tree", "status", "diff", "log", "cat-file", "ls-files", "config",
                  "check-ignore", "check-attr", "show-ref", "for-each-ref", "describe", "symbolic-ref"}

    def test_no_bare_git_inspection_remains(self) -> None:
        import ast

        offenders = []
        files = sorted((ROOT / "scripts" / "cwo_core").glob("*.py")) + sorted((ROOT / "scripts").glob("*.py"))
        for path in files:
            if path.name == "workspace_capture.py":
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"run", "Popen", "check_output", "check_call"}):
                    continue
                if not node.args or not isinstance(node.args[0], ast.List):
                    continue
                words = [item.value for item in node.args[0].elts if isinstance(item, ast.Constant) and isinstance(item.value, str)]
                if words[:1] == ["git"] and self.INSPECTION & set(words):
                    offenders.append(f"{path.name}:{node.lineno}")
        self.assertEqual(offenders, [], "inspection must use the trusted executable")

    def test_trusted_ancestry_check_ignores_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
            marker = base / "FAKE_GIT_RAN"
            fake = base / "bin" / "git"
            fake.parent.mkdir()
            fake.write_text(f"#!/bin/sh\ntouch {marker}\nexit 0\n", encoding="utf-8")
            fake.chmod(0o755)
            with mock.patch.dict(os.environ, {"PATH": f"{fake.parent}:{os.environ.get('PATH', '')}"}):
                yes = workspace_capture.trusted_git_completed(repo, ["merge-base", "--is-ancestor", head, head])
                no = workspace_capture.trusted_git_completed(repo, ["merge-base", "--is-ancestor", head, "0" * 40])
            self.assertFalse(marker.exists(), "the fake git on PATH never ran")
        self.assertEqual(yes.returncode, 0)
        self.assertNotEqual(no.returncode, 0)

    def test_discovery_requires_positive_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            broken = base / "broken"
            broken.mkdir()
            (broken / ".git").write_text("gitdir: /nonexistent/gitdir\n", encoding="utf-8")
            with self.assertRaises(workspace_capture.WorkspaceDiscoveryError):
                workspace_capture.worktree_top_level(broken)
            spaced = base / "repo "
            spaced.mkdir()
            subprocess.run(["git", "init", "-q", str(spaced)], check=True)
            configure_git_fixture(spaced)
            subprocess.run(["git", "init", "-q", str(base / "repo")], check=True)
            configure_git_fixture(base / "repo")
            self.assertEqual(workspace_capture.worktree_top_level(spaced), str(spaced))

    def _fifo_writer(self, path: Path) -> tuple[object, object]:
        import threading

        woke = threading.Event()

        def writer() -> None:
            try:
                fd = os.open(path, os.O_WRONLY)
            except OSError:
                return
            woke.set()
            os.close(fd)

        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        return woke, thread

    def _release(self, path: Path, thread: object) -> None:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        except OSError:
            return
        thread.join(5)
        os.close(fd)

    def test_special_repository_files_are_refused_before_git_runs(self) -> None:
        cases = {
            "config include": lambda repo, base: (git(repo, "config", "include.path", str(base / "include.fifo")), base / "include.fifo")[1],
            "index": lambda repo, base: (os.unlink(repo / ".git" / "index"), repo / ".git" / "index")[1],
            "head reference": lambda repo, base: (os.unlink(repo / ".git" / subprocess.run(["git", "-C", str(repo), "symbolic-ref", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()), repo / ".git" / subprocess.run(["git", "-C", str(repo), "symbolic-ref", "HEAD"], check=True, capture_output=True, text=True).stdout.strip())[1],
            "worktree .gitignore": lambda repo, base: repo / "docs" / ".gitignore",
        }
        for label, prepare in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmpdir:
                base = Path(tmpdir)
                repo = make_repo(base)
                fifo = prepare(repo, base)
                os.mkfifo(fifo)
                woke, thread = self._fifo_writer(fifo)
                started = time.monotonic()
                try:
                    evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                    self.assertTrue(evidence["incomplete"])
                    self.assertLess(time.monotonic() - started, 20)
                    self.assertFalse(woke.wait(0.5), "no process may open the FIFO")
                finally:
                    self._release(fifo, thread)

    def test_discovery_checks_repository_files_before_git_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            fifo = base / "include.fifo"
            git(repo, "config", "include.path", str(fifo))
            os.mkfifo(fifo)
            woke, thread = self._fifo_writer(fifo)
            try:
                with self.assertRaises(workspace_capture.WorkspaceDiscoveryError):
                    workspace_capture.worktree_top_level(repo / "src")
                with self.assertRaises(workspace.WorkspaceInspectionError):
                    workspace.worktree_state_digest(repo)
                self.assertFalse(woke.wait(0.5), "no process may open the FIFO")
            finally:
                self._release(fifo, thread)

    def test_discovery_refuses_a_top_level_elsewhere(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            elsewhere = base / "elsewhere"
            elsewhere.mkdir()
            git(repo, "config", "core.worktree", str(elsewhere))
            with self.assertRaises(workspace_capture.WorkspaceDiscoveryError):
                workspace_capture.worktree_top_level(repo)

    def test_git_output_and_reads_are_charged_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            git_exe = workspace_capture.trusted_git()
            budget = workspace_capture.Budget.start(max_files=0, max_bytes=1 << 20, max_seconds=30, max_entries=0)
            workspace_capture.run_git(git_exe, repo, ["ls-files", "-s"], budget=budget)
            self.assertGreater(budget.bytes, 0, "git output is charged to the budget")
            tight = workspace_capture.Budget.start(max_files=0, max_bytes=4, max_seconds=30, max_entries=0)
            with self.assertRaises(workspace_capture.BudgetExhausted):
                workspace_capture.run_git(git_exe, repo, ["ls-files", "-s"], budget=tight)
            root_fd = os.open(repo, os.O_RDONLY | os.O_DIRECTORY)
            try:
                info = os.stat("src/app.py", dir_fd=root_fd, follow_symlinks=False)
                src_fd = os.open("src", os.O_RDONLY | os.O_DIRECTORY, dir_fd=root_fd)
                try:
                    with self.assertRaises(workspace_capture.BudgetExhausted):
                        workspace_capture._read_pinned(src_fd, "app.py", info, 1024, deadline=time.monotonic() - 1)
                finally:
                    os.close(src_fd)
            finally:
                os.close(root_fd)

    def test_index_only_attributes_make_cleanliness_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            (repo / ".gitattributes").write_text("*.txt text\n", encoding="utf-8")
            git(repo, "add", ".gitattributes")
            git(repo, "commit", "-qm", "attrs")
            git(repo, "update-index", "--skip-worktree", ".gitattributes")
            (repo / ".gitattributes").unlink()
            state = capture_tracked_workspace_state(repo)
        self.assertEqual(state["git_cleanliness"], "unknown-conversions")

    def test_require_clean_needs_established_cleanliness(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            (repo / ".gitattributes").write_text("*.py filter=lfs\n", encoding="utf-8")
            git(repo, "add", ".gitattributes")
            git(repo, "commit", "-qm", "attrs")
            state = capture_tracked_workspace_state(repo)
        self.assertEqual(state["tracked_status"], [])
        content = workspace.diff_workspace_state(state, state, require_clean=True)
        plain = {k: v for k, v in state.items() if k != "content_fingerprints"}
        legacy_branch = workspace.diff_workspace_state(plain, plain, require_clean=True)
        self.assertTrue(content["unexpected_mutation_detected"])
        self.assertTrue(legacy_branch["unexpected_mutation_detected"])

    def test_root_mode_change_is_a_metadata_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            os.chmod(repo, 0o700)
            after = capture_workspace_baseline(repo, allowed_paths=["src"])
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
        self.assertIn(".git:capture-identity", {change["path"] for change in report["git_metadata_changes"]})



class RoundFiveTests(unittest.TestCase):
    """Gitdir indirection, read deadlines and declared content boundaries."""

    def test_discovery_errors_are_never_absence(self) -> None:
        real_lstat = os.lstat

        def denied(path: object, *args: object, **kwargs: object) -> os.stat_result:
            if str(path).endswith("/.git"):
                raise PermissionError(13, "Permission denied", str(path))
            return real_lstat(path, *args, **kwargs)

        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            with mock.patch.object(workspace_capture.os, "lstat", side_effect=denied):
                with self.assertRaises(workspace_capture.WorkspaceDiscoveryError):
                    workspace_capture.worktree_top_level(repo / "src")
                with self.assertRaises(workspace.WorkspaceInspectionError):
                    workspace.worktree_state_digest(repo)

    def test_gitdir_indirection_is_read_byte_for_byte(self) -> None:
        import threading

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            (base / "decoy-parent").mkdir()
            decoy = make_repo(base / "decoy-parent")
            spaced = base / "gd "
            (repo / ".git").rename(spaced)
            # The sibling without the trailing space is another repository's gitdir.
            (decoy / ".git").rename(base / "gd")
            (repo / ".git").write_bytes(b"gitdir: " + os.fsencode(spaced) + b"\n")
            evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
            self.assertFalse(evidence["incomplete"], evidence.get("incomplete_reasons"))
            self.assertEqual(workspace_capture.worktree_top_level(repo), str(repo))
            # A FIFO in the real gitdir is found; checking the sibling would miss it.
            fifo = spaced / "info" / "exclude"
            fifo.unlink(missing_ok=True)
            os.mkfifo(fifo)
            woke = threading.Event()

            def writer() -> None:
                try:
                    fd = os.open(fifo, os.O_WRONLY)
                except OSError:
                    return
                woke.set()
                os.close(fd)

            thread = threading.Thread(target=writer, daemon=True)
            thread.start()
            try:
                refused = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertTrue(refused["incomplete"])
                self.assertFalse(woke.wait(0.5), "no process may open the FIFO")
            finally:
                try:
                    fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
                    thread.join(5)
                    os.close(fd)
                except OSError:
                    pass

    def test_preflight_directories_must_be_the_ones_git_uses(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            (base / "other").mkdir()
            elsewhere = make_repo(base / "other")
            real_dirs = workspace_capture.WorktreeCapture._dirs

            def other_dirs(capture: object) -> tuple[str, str, str]:
                git_dir, common, top = real_dirs(capture)
                return str(elsewhere / ".git"), str(elsewhere / ".git"), top

            with mock.patch.object(workspace_capture.WorktreeCapture, "_dirs", other_dirs):
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
        self.assertTrue(evidence["incomplete"])
        self.assertIn("other than the one checked", " ".join(evidence["incomplete_reasons"]))

    def test_layouts_that_open_more_files_are_refused_before_git_runs(self) -> None:
        def chained(repo: Path) -> None:
            branch = subprocess.run(["git", "-C", str(repo), "symbolic-ref", "HEAD"], check=True, capture_output=True,
                                    text=True).stdout.strip()
            git(repo, "branch", "other")
            (repo / ".git" / branch).write_text("ref: refs/heads/other\n", encoding="utf-8")

        cases = {
            "chained symbolic reference": (chained, "chained symbolic references"),
            "split index": (lambda repo: (repo / ".git" / ("sharedindex." + "0" * 40)).write_bytes(b""), "split indexes"),
        }
        for label, (prepare, reason) in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                prepare(repo)
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertTrue(evidence["incomplete"])
                self.assertIn(reason, " ".join(evidence["incomplete_reasons"]))

    def test_special_file_directly_in_the_gitdir_is_never_opened(self) -> None:
        import threading

        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            fifo = repo / ".git" / "MERGE_HEAD"
            os.mkfifo(fifo)
            woke = threading.Event()

            def writer() -> None:
                try:
                    fd = os.open(fifo, os.O_WRONLY)
                except OSError:
                    return
                woke.set()
                os.close(fd)

            thread = threading.Thread(target=writer, daemon=True)
            thread.start()
            try:
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertTrue(evidence["incomplete"])
                self.assertFalse(woke.wait(0.5), "no process may open the FIFO")
            finally:
                try:
                    fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
                    thread.join(5)
                    os.close(fd)
                except OSError:
                    pass

    def test_entries_are_charged_while_directories_are_listed(self) -> None:
        real_scandir = os.scandir
        consumed: list[int] = []

        class Counting:
            """A scandir iterator that counts the entries actually consumed."""

            def __init__(self, inner: object) -> None:
                self.inner = inner
                consumed.append(0)

            def __enter__(self) -> "Counting":
                return self

            def __exit__(self, *exc: object) -> None:
                self.inner.close()

            def __iter__(self) -> "Counting":
                return self

            def __next__(self) -> object:
                entry = next(self.inner)
                consumed[-1] += 1
                return entry

        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            crowded = repo / ".git" / "objects" / "info"
            crowded.mkdir(parents=True, exist_ok=True)
            for index in range(200):
                (crowded / f"entry-{index}").write_bytes(b"")
            with mock.patch.object(workspace_capture, "METADATA_ENTRIES", 60), \
                    mock.patch.object(workspace_capture.os, "scandir", side_effect=lambda fd: Counting(real_scandir(fd))):
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
        self.assertTrue(evidence["incomplete"])
        self.assertIn("budget", " ".join(evidence["incomplete_reasons"]))
        self.assertLessEqual(max(consumed), 61, "listing stops once the entry budget is spent")

    def test_every_capture_read_carries_the_deadline(self) -> None:
        calls: list[object] = []
        real_read = workspace_capture._read_pinned

        def recording(*args: object, **kwargs: object) -> bytes:
            calls.append(kwargs.get("deadline"))
            return real_read(*args, **kwargs)

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            cache = repo / "build" / "__pycache__"
            cache.mkdir(parents=True)
            (cache / "tracked.pyc").write_bytes(b"excluded but tracked")
            git(repo, "add", "-f", "build/__pycache__/tracked.pyc")
            (repo / ".gitattributes").write_text("*.md text\n", encoding="utf-8")
            git(repo, "add", ".gitattributes")
            git(repo, "commit", "-qm", "more")
            hooks = base / "hooks"
            hooks.mkdir()
            (hooks / "pre-commit").write_text("#!/bin/sh\n", encoding="utf-8")
            (repo / ".git" / "hooks").rename(base / "old-hooks")
            (repo / ".git" / "hooks").symlink_to(hooks)
            with mock.patch.object(workspace_capture, "_read_pinned", side_effect=recording):
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
        self.assertFalse(evidence["incomplete"], evidence.get("incomplete_reasons"))
        self.assertTrue(calls)
        self.assertNotIn(None, calls, "every read path passes the shared deadline")

    def test_pool_admission_requires_established_cleanliness(self) -> None:
        from cwo_core.native_pool_workspace import PoolWorkspaceError, _require_clean_complete_baseline

        clean = {"incomplete": False, "baseline_complete": True, "tracked_status": [], "evidence_version": 3,
                 "git_cleanliness": "raw-equals-git"}
        _require_clean_complete_baseline(clean)
        with self.assertRaisesRegex(PoolWorkspaceError, "workspace-baseline-cleanliness-unknown"):
            _require_clean_complete_baseline({**clean, "git_cleanliness": "unknown-conversions"})
        with self.assertRaisesRegex(PoolWorkspaceError, "workspace-baseline-cleanliness-unknown"):
            _require_clean_complete_baseline({key: value for key, value in clean.items() if key != "git_cleanliness"})

    def test_declared_content_is_kept_without_untracked_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            cache = repo / "src" / "__pycache__"
            cache.mkdir()
            (cache / "cache").write_bytes(b"one")
            (repo / "src" / "newdir").mkdir()
            before = capture_workspace_baseline(repo, allowed_paths=["src"], include_untracked=False)
            (cache / "cache").write_bytes(b"two")
            os.chmod(repo / "src" / "newdir", 0o700)
            after = capture_workspace_baseline(repo, allowed_paths=["src"], include_untracked=False)
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
        self.assertFalse(before["incomplete"] or after["incomplete"])
        self.assertIn("src/__pycache__/cache", before["raw_inventory"])
        self.assertIn("src/newdir", before["raw_inventory"])
        self.assertTrue(report["mutation_detected"])
        self.assertIn("src/__pycache__/cache", report["mutation_categories"]["scoped"])
        self.assertIn("src/newdir", report["mutation_categories"]["scoped"])


def fifo_writer(path: Path) -> tuple[object, object]:
    """A thread blocked opening ``path`` for writing; its event is set if anything opens it for reading."""
    import threading

    woke = threading.Event()

    def writer() -> None:
        try:
            fd = os.open(path, os.O_WRONLY)
        except OSError:
            return
        woke.set()
        os.close(fd)

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    return woke, thread


def release(path: Path, thread: object) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return
    thread.join(5)  # type: ignore[attr-defined]
    os.close(fd)


class RoundSixTests(unittest.TestCase):
    """Ignored paths, linked-worktree metadata and qualified Git releases."""

    def test_gitignore_in_an_excluded_directory_is_never_opened(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            cache = repo / "docs" / "__pycache__"
            cache.mkdir()
            (cache / "module.pyc").write_bytes(b"cache")
            fifo = cache / ".gitignore"
            os.mkfifo(fifo)
            woke, thread = fifo_writer(fifo)
            try:
                # Git classifies ignores on a private mirror, so nothing in an
                # excluded directory is opened and the capture stays complete.
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertFalse(evidence["incomplete"], evidence.get("incomplete_reasons"))
                self.assertFalse(woke.wait(0.5), "no process may open the FIFO")
            finally:
                release(fifo, thread)

    def test_inspection_helpers_qualify_the_repository_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            fifo = base / "include.fifo"
            git(repo, "config", "include.path", str(fifo))
            os.mkfifo(fifo)
            woke, thread = fifo_writer(fifo)
            try:
                result = workspace_capture.trusted_git_completed(repo, ["rev-parse", "HEAD"])
                self.assertEqual(result.returncode, 128)
                self.assertIn(b"not safe for git to read", result.stderr)
                with self.assertRaises(workspace_capture.WorkspaceDiscoveryError):
                    workspace_capture.trusted_git_output(repo, ["rev-parse", "HEAD"])
                with self.assertRaises(workspace_capture.WorkspaceDiscoveryError):
                    workspace_capture.trusted_git_succeeds(repo, ["merge-base", "--is-ancestor", "HEAD", "HEAD"])
                self.assertFalse(woke.wait(0.5), "no process may open the FIFO")
            finally:
                release(fifo, thread)
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            self.assertEqual(workspace_capture.trusted_git_completed(repo, ["rev-parse", "HEAD"]).returncode, 0)

    def test_ancestors_survive_without_untracked_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            before = capture_workspace_baseline(repo, allowed_paths=["src/app.py"], include_untracked=False)
            os.chmod(repo / "src", 0o700)
            after = capture_workspace_baseline(repo, allowed_paths=["src/app.py"], include_untracked=False)
            report = compare_workspace_baseline(before, after, allowed_paths=["src/app.py"])
        self.assertIn("src", before["raw_inventory"])
        self.assertTrue(report["mutation_detected"])
        self.assertTrue(report["unexpected_mutation_detected"], "changing an existing ancestor stays unexpected")

    def test_linked_worktree_info_is_snapshotted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            linked = base / "linked"
            git(repo, "worktree", "add", "-q", str(linked))
            gitdir = Path(subprocess.run(["git", "-C", str(linked), "rev-parse", "--path-format=absolute", "--git-dir"],
                                         check=True, capture_output=True, text=True).stdout.strip())
            (gitdir / "info").mkdir(exist_ok=True)
            (gitdir / "info" / "sparse-checkout").write_text("/*\n", encoding="utf-8")
            before = capture_workspace_baseline(linked, allowed_paths=["src"])
            (gitdir / "info" / "sparse-checkout").write_text("/src/\n", encoding="utf-8")
            after = capture_workspace_baseline(linked, allowed_paths=["src"])
            report = compare_workspace_baseline(before, after, allowed_paths=["src"])
        self.assertFalse(before["incomplete"] or after["incomplete"], before.get("incomplete_reasons"))
        self.assertIn("gitdir:info/sparse-checkout", {change["path"].split(":", 1)[1] for change in report["git_metadata_changes"]})
        self.assertTrue(report["unexpected_mutation_detected"])

    def test_only_qualified_git_releases_are_accepted(self) -> None:
        for version, accepted in (((2, 34, 9), False), ((2, 35, 0), True), ((2, 43, 0), True), ((2, 56, 1), True),
                                  ((2, 57, 0), False), ((3, 0, 0), False)):
            with self.subTest(version=version), mock.patch.dict(workspace_capture._GIT_CACHE, clear=True), \
                    mock.patch.object(workspace_capture, "_version", return_value=version):
                git = workspace_capture.trusted_git()
                self.assertEqual(git is not None, accepted)

    def test_pool_common_dir_keeps_trailing_whitespace(self) -> None:
        from cwo_core.native_pool_workspace import _git_common_dir

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            spaced = base / "gd "
            (repo / ".git").rename(spaced)
            (repo / ".git").write_bytes(b"gitdir: " + os.fsencode(spaced) + b"\n")
            self.assertEqual(_git_common_dir(repo), spaced.resolve())


class RoundSevenTests(unittest.TestCase):
    """Bare repositories, unchecked ignore files and private repository boundaries."""

    def _include_fifo(self, config: Path, base: Path) -> Path:
        fifo = base / "include.fifo"
        os.mkfifo(fifo)
        with config.open("a", encoding="utf-8") as handle:
            handle.write(f"[include]\n\tpath = {fifo}\n")
        return fifo

    def test_a_bare_repository_without_a_git_entry_is_never_used(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            bare = base / "bare.git"
            subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
            configure_git_fixture(bare)
            fifo = self._include_fifo(bare / "config", base)
            woke, thread = fifo_writer(fifo)
            try:
                for root in (bare, bare / "refs"):
                    with self.subTest(root=root.name):
                        result = workspace_capture.trusted_git_completed(root, ["rev-parse", "--git-dir"])
                        self.assertEqual(result.returncode, 128)
                        self.assertIn(b"no .git entry", result.stderr)
                        with self.assertRaises(workspace_capture.WorkspaceDiscoveryError):
                            workspace_capture.trusted_git_output(root, ["rev-parse", "--git-dir"])
                        with self.assertRaises(workspace_capture.WorkspaceDiscoveryError):
                            workspace_capture.trusted_git_succeeds(root, ["merge-base", "--is-ancestor", "HEAD", "HEAD"])
                        self.assertIsNone(workspace_capture.worktree_top_level(root))
                self.assertFalse(woke.wait(0.5), "no process may open the FIFO")
            finally:
                release(fifo, thread)

    def test_a_nested_bare_repository_cannot_take_over_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            nested = repo / "vendor" / "nested.git"
            nested.parent.mkdir()
            subprocess.run(["git", "init", "-q", "--bare", str(nested)], check=True)
            configure_git_fixture(nested)
            fifo = self._include_fifo(nested / "config", base)
            woke, thread = fifo_writer(fifo)
            try:
                git_dir = workspace_capture.trusted_git_output(nested, ["rev-parse", "--path-format=absolute", "--git-dir"])
                self.assertEqual(Path(git_dir), (repo / ".git").resolve(), "Git is bound to the checked repository")
                self.assertEqual(workspace_capture.worktree_top_level(nested), str(repo.resolve()))
                self.assertFalse(woke.wait(0.5), "no process may open the FIFO")
            finally:
                release(fifo, thread)

    def test_ignore_checks_never_open_an_unchecked_gitignore(self) -> None:
        from validate_repository import validate_retired_beads_context_aliases

        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            (repo / "docs" / "new.md").write_text("draft\n", encoding="utf-8")
            fifo = repo / "docs" / ".gitignore"
            os.mkfifo(fifo)
            woke, thread = fifo_writer(fifo)
            try:
                with self.assertRaisesRegex(workspace_capture.WorkspaceDiscoveryError, "not a regular file"):
                    workspace_capture.trusted_git_ignored(repo, ["docs/new.md"])
                errors: list[str] = []
                validate_retired_beads_context_aliases(errors, repo_root=repo)
                self.assertFalse(woke.wait(0.5), "no process may open the FIFO")
            finally:
                release(fifo, thread)

    def test_ignore_checks_answer_for_checked_ignore_files_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            (repo / "docs" / ".gitignore").write_text("ignored.md\n", encoding="utf-8")
            (repo / "docs" / "ignored.md").write_text("x\n", encoding="utf-8")
            (repo / "docs" / "kept.md").write_text("x\n", encoding="utf-8")
            self.assertEqual(workspace_capture.trusted_git_ignored(repo, ["docs/ignored.md", "docs/kept.md", "src/app.py"]),
                             {"docs/ignored.md"})
            outside = base / "outside"
            outside.mkdir()
            (outside / ".gitignore").write_text("*\n", encoding="utf-8")
            (repo / "linked").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(workspace_capture.WorkspaceDiscoveryError, "symlink"):
                workspace_capture.trusted_git_ignored(repo, ["linked/file.md"])

    def test_attributes_in_an_excluded_directory_make_cleanliness_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            cache = repo / "docs" / "__pycache__"
            cache.mkdir()
            (cache / "data.txt").write_text("tracked\n", encoding="utf-8")
            git(repo, "add", "-f", "docs/__pycache__/data.txt")
            git(repo, "commit", "-qm", "tracked file in an excluded directory")
            self.assertTrue(workspace.workspace_is_clean(repo, include_untracked=False))
            (cache / ".gitattributes").write_text("*.txt filter=evil\n", encoding="utf-8")
            state = capture_tracked_workspace_state(repo)
            self.assertEqual(state["tracked_status"], [])
            self.assertEqual(state["git_cleanliness"], "unknown-conversions")
            self.assertFalse(workspace.workspace_is_clean(repo, include_untracked=False))
            (cache / ".gitattributes").unlink()
            os.mkfifo(cache / ".gitattributes")
            self.assertFalse(workspace.workspace_is_clean(repo, include_untracked=False), "an unreadable source is unknown, too")

    def test_shallow_history_changes_are_metadata_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            first = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
            (repo / "src" / "more.py").write_text("print('b')\n", encoding="utf-8")
            git(repo, "add", "-A")
            git(repo, "commit", "-qm", "second")
            second = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
            shallow = repo / ".git" / "shallow"
            steps = {
                "added": (None, f"{second}\n"),
                "modified": (f"{second}\n", f"{first}\n"),
                "deleted": (f"{first}\n", None),
            }
            for label, (old, new) in steps.items():
                with self.subTest(change=label):
                    shallow.unlink(missing_ok=True)
                    if old is not None:
                        shallow.write_text(old, encoding="utf-8")
                    before = capture_workspace_baseline(repo, allowed_paths=["src"])
                    shallow.unlink(missing_ok=True)
                    if new is not None:
                        shallow.write_text(new, encoding="utf-8")
                    after = capture_workspace_baseline(repo, allowed_paths=["src"])
                    report = compare_workspace_baseline(before, after, allowed_paths=["src"])
                    self.assertFalse(before["incomplete"] or after["incomplete"], before.get("incomplete_reasons"))
                    self.assertIn("common:shallow", {change["path"].split(":", 1)[1] for change in report["git_metadata_changes"]})
                    self.assertTrue(report["unexpected_mutation_detected"])

    def test_private_repositories_never_reach_an_enclosing_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            index_before = (repo / ".git" / "index").read_bytes()
            scratch = repo / "scratch"
            scratch.mkdir()
            self.assertNotEqual(workspace_capture.trusted_git_private(scratch, ["rev-parse", "--git-dir"]).returncode, 0,
                                "the enclosing repository is not discovered")
            for args in (["init", "-q"], ["config", "--local", "maintenance.auto", "false"],
                         ["config", "--local", "gc.auto", "0"], ["config", "user.name", "t"],
                         ["config", "user.email", "t@example.invalid"]):
                self.assertEqual(workspace_capture.trusted_git_private(scratch, args).returncode, 0)
            (scratch / "file.txt").write_text("x\n", encoding="utf-8")
            self.assertEqual(workspace_capture.trusted_git_private(scratch, ["add", "."]).returncode, 0)
            self.assertEqual(workspace_capture.trusted_git_private(scratch, ["commit", "-qm", "scratch"]).returncode, 0)
            self.assertTrue((scratch / ".git").is_dir())
            self.assertEqual((repo / ".git" / "index").read_bytes(), index_before, "the enclosing index is untouched")


def write_loose(repo: Path, kind: str, content: bytes) -> str:
    """Store ``content`` as a loose SHA-1 object without Git, so malformed objects can be planted."""
    import hashlib
    import zlib

    data = f"{kind} {len(content)}\0".encode() + content
    oid = hashlib.sha1(data).hexdigest()
    path = repo / ".git" / "objects" / oid[:2] / oid[2:]
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(zlib.compress(data))
    return oid


def plant_commit(repo: Path, tree_content: bytes) -> str:
    """Write a tree with exactly ``tree_content`` and a commit of it, and point HEAD's branch at the commit."""
    tree = write_loose(repo, "tree", tree_content)
    commit = write_loose(repo, "commit", f"tree {tree}\nauthor t <t@example.invalid> 0 +0000\n"
                                         f"committer t <t@example.invalid> 0 +0000\n\nplanted\n".encode())
    point_head_at(repo, commit)
    return commit


def point_head_at(repo: Path, oid: str) -> None:
    reference = (repo / ".git" / "HEAD").read_text(encoding="utf-8").split(":", 1)[1].strip()
    (repo / ".git" / reference).write_text(oid + "\n", encoding="utf-8")


def tree_entry(mode: str, name: str, oid: str) -> bytes:
    return f"{mode} {name}".encode() + b"\0" + bytes.fromhex(oid)


def pack_entry_header(kind: int, size: int) -> bytes:
    byte = (kind << 4) | (size & 15)
    size >>= 4
    out = bytearray()
    while size:
        out.append(byte | 0x80)
        byte = size & 0x7F
        size >>= 7
    out.append(byte)
    return bytes(out)


def ofs_distance(distance: int) -> bytes:
    """An offset delta's base distance, encoded as pack-objects writes it."""
    out = [distance & 0x7F]
    distance >>= 7
    while distance:
        distance -= 1
        out.append(0x80 | (distance & 0x7F))
        distance >>= 7
    return bytes(reversed(out))


def delta_size(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if not value:
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


def write_pack(directory: Path, entries: list[tuple[bytes, bytes]], *, trailer: bool = True) -> None:
    """A version 2 pack and index holding ``entries`` (object identifier, raw entry bytes) in order."""
    import hashlib
    import struct

    directory.mkdir(parents=True, exist_ok=True)
    body = bytearray()
    offsets: dict[bytes, int] = {}
    for oid, raw in entries:
        offsets[oid] = 12 + len(body)
        body += raw
    pack = b"PACK" + struct.pack(">II", 2, len(entries)) + bytes(body)
    checksum = hashlib.sha1(pack).digest()
    names = sorted(offsets)
    index = b"\xfftOc" + struct.pack(">I", 2)
    index += b"".join(struct.pack(">I", sum(1 for name in names if name[0] <= bucket)) for bucket in range(256))
    index += b"".join(names) + b"\0\0\0\0" * len(names) + b"".join(struct.pack(">I", offsets[name]) for name in names)
    index += checksum + hashlib.sha1(index + checksum).digest()
    (directory / "pack-test.pack").write_bytes(pack + checksum if trailer else pack)
    (directory / "pack-test.idx").write_bytes(index)


def blob_entry(data: bytes) -> tuple[str, bytes]:
    import hashlib
    import zlib

    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest(), pack_entry_header(3, len(data)) + zlib.compress(data)


def offset_delta_entry(distance: int, delta: bytes) -> bytes:
    import zlib

    return pack_entry_header(6, len(delta)) + ofs_distance(distance) + zlib.compress(delta)


def object_store(objects: Path, *, max_object_bytes: int, charges: list[int] | None = None, check_time=lambda: None):
    from cwo_core.git_store import ObjectStore

    return ObjectStore(str(objects), hash_name="sha1", open_regular=lambda path: os.open(path, os.O_RDONLY),
                       list_names=os.listdir, charge=(charges if charges is not None else []).append,
                       check_time=check_time, max_object_bytes=max_object_bytes)


def untracked_status(repo: Path) -> list[str]:
    raw = subprocess.run(["git", "-C", str(repo), "status", "--porcelain=v1", "-z", "--untracked-files=all"],
                         check=True, capture_output=True).stdout
    return sorted(record.decode() for record in raw.split(b"\0") if record.startswith(b"?? "))


class RoundEightTests(unittest.TestCase):
    """Scratch isolation, Git configuration and bounded object metadata."""

    def test_scratch_never_lies_inside_the_workspace_or_its_repository(self) -> None:
        calls: list[str] = []
        real = workspace_capture.run_git

        def recording(git: object, root: object, args: list[str], **kwargs: object) -> object:
            calls.append(str(kwargs.get("git_dir")))
            return real(git, root, args, **kwargs)  # type: ignore[arg-type]

        for inside in ("tmp", ".git/tmp"):
            with self.subTest(temporary_directory=inside), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                scratch = repo / inside
                scratch.mkdir()
                calls.clear()
                with mock.patch.object(tempfile, "tempdir", str(scratch)), \
                        mock.patch.object(workspace_capture, "run_git", side_effect=recording):
                    state = capture_tracked_workspace_state(repo, include_untracked=True)
                self.assertFalse(state["incomplete"], state.get("incomplete_reasons"))
                self.assertEqual(list(scratch.iterdir()), [], "nothing is written inside the workspace or its repository")
                self.assertEqual([path for path in state["raw_inventory"] if "cwo-inspect" in path], [])
                self.assertEqual(len(calls), 2)
                for git_dir in calls:
                    self.assertFalse(os.path.realpath(git_dir).startswith(os.path.realpath(repo) + os.sep), git_dir)
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            (repo / "tmp").mkdir()
            inside = {"TMPDIR": str(repo / "tmp"), "TEMP": str(repo / "tmp"), "TMP": str(repo / "tmp")}
            with mock.patch.object(tempfile, "tempdir", str(repo / "tmp")), mock.patch.dict(os.environ, inside), \
                    mock.patch.object(workspace_capture, "SCRATCH_PARENTS", (str(repo), str(repo / ".git"))):
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
            self.assertTrue(evidence["incomplete"])
            self.assertIn("no scratch directory outside", " ".join(evidence["incomplete_reasons"]))
            self.assertEqual(list((repo / "tmp").iterdir()), [])

    def test_config_worktree_applies_only_with_its_extension(self) -> None:
        for enabled in (False, True):
            with self.subTest(extension=enabled), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                (repo / ".gitignore").write_text("*.LOG\n", encoding="utf-8")
                (repo / "debug.log").write_text("x\n", encoding="utf-8")
                (repo / ".git" / "config.worktree").write_text("[core]\n\tignorecase = true\n", encoding="utf-8")
                if enabled:
                    git(repo, "config", "extensions.worktreeConfig", "true")
                expected = untracked_status(repo)
                self.assertEqual("?? debug.log" in expected, not enabled, "the fixture separates the two cases")
                state = capture_tracked_workspace_state(repo, include_untracked=True)
                self.assertFalse(state["incomplete"], state.get("incomplete_reasons"))
                self.assertEqual(sorted(line for line in state["tracked_status"] if line.startswith("?? ")), expected)

    def test_booleans_are_read_as_git_reads_them(self) -> None:
        refused = (("core.bare", "2"), ("core.bare", "maybe"), ("core.ignorecase", "junk"),
                   ("core.sparseCheckout", "1x"), ("extensions.worktreeConfig", "maybe"))
        for key, value in refused:
            with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                git(repo, "config", key, value)
                with self.assertRaises(workspace_capture.WorkspaceDiscoveryError):
                    workspace_capture.worktree_top_level(repo)
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertTrue(evidence["incomplete"])
        for value in ("2", "0x1", "on", "0"):
            with self.subTest(ignorecase=value), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                (repo / ".gitignore").write_text("*.LOG\n", encoding="utf-8")
                (repo / "debug.log").write_text("x\n", encoding="utf-8")
                git(repo, "config", "core.ignorecase", value)
                expected = untracked_status(repo)
                self.assertEqual("?? debug.log" in expected, value == "0", "Git reads the value as this boolean")
                state = capture_tracked_workspace_state(repo, include_untracked=True)
                self.assertFalse(state["incomplete"], state.get("incomplete_reasons"))
                self.assertEqual(sorted(line for line in state["tracked_status"] if line.startswith("?? ")), expected)

    def test_format_settings_git_refuses_are_refused(self) -> None:
        cases = {
            "a format version without a value": "[core]\n\trepositoryformatversion\n",
            "an object format in capitals": "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectFormat = SHA1\n",
            "an object format without a value": "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectFormat\n",
            "a reference storage in capitals": "[core]\n\trepositoryformatversion = 1\n[extensions]\n\trefStorage = FILES\n",
            "a partial clone remote without a value": "[extensions]\n\tpartialClone\n",
        }
        for label, text in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                config = repo / ".git" / "config"
                config.write_text(config.read_text(encoding="utf-8").replace("\trepositoryformatversion = 0\n", "") + text,
                                  encoding="utf-8")
                status = subprocess.run(["git", "-C", str(repo), "status"], capture_output=True)
                self.assertNotEqual(status.returncode, 0, "Git refuses the repository too")
                with self.assertRaises(workspace_capture.WorkspaceDiscoveryError):
                    workspace_capture.worktree_top_level(repo)

    def test_special_attribute_files_anywhere_make_cleanliness_unknown(self) -> None:
        for kind in ("fifo", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                self.assertTrue(workspace.workspace_is_clean(repo, include_untracked=False))
                attributes = repo / "docs" / ".gitattributes"
                thread = None
                if kind == "fifo":
                    os.mkfifo(attributes)
                    woke, thread = fifo_writer(attributes)
                else:
                    (Path(tmpdir) / "outside").write_text("*.md filter=evil\n", encoding="utf-8")
                    attributes.symlink_to(Path(tmpdir) / "outside")
                try:
                    self.assertFalse(workspace.workspace_is_clean(repo, include_untracked=False))
                    # What the canaries' unbound fallback captures and checks.
                    state = capture_tracked_workspace_state(repo, include_untracked=True, include_content_fingerprints=False)
                    self.assertFalse(state["incomplete"], state.get("incomplete_reasons"))
                    self.assertEqual(state["git_cleanliness"], "unknown-conversions")
                    self.assertFalse(workspace.cleanliness_established(state))
                    if thread is not None:
                        self.assertFalse(woke.wait(0.5), "no process may open the FIFO")
                finally:
                    if thread is not None:
                        release(attributes, thread)

    def test_references_are_read_as_git_reads_them(self) -> None:
        def packed(repo: Path) -> bytes:
            git(repo, "pack-refs", "--all")
            return (repo / ".git" / "packed-refs").read_bytes()

        malformed = {
            "a line that is not a reference": lambda data: data + b"not a reference line\n",
            "an empty line": lambda data: data.replace(b"\n", b"\n\n", 1),
            "no final newline": lambda data: data.rstrip(b"\n"),
            "a peel that follows no reference": lambda data: data.replace(b"\n", b"\n^" + b"a" * 40 + b"\n", 1),
            "an invalid name": lambda data: data + b"a" * 40 + b" refs/heads/bad..name\n",
        }
        for label, change in malformed.items():
            with self.subTest(packed_refs=label), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                (repo / ".git" / "packed-refs").write_bytes(change(packed(repo)))
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertTrue(evidence["incomplete"])
                self.assertIn("packed-refs", " ".join(evidence["incomplete_reasons"]))
        for target, unborn in (("refs/tags/missing", False), ("refs/remotes/origin/missing", False), ("refs/heads/fresh", True)):
            with self.subTest(head=target), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                (repo / ".git" / "HEAD").write_text(f"ref: {target}\n", encoding="utf-8")
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                if unborn:
                    self.assertFalse(evidence["incomplete"], evidence.get("incomplete_reasons"))
                    self.assertEqual(evidence["head"], "unborn")
                else:
                    self.assertTrue(evidence["incomplete"])
                    self.assertIn("missing reference outside refs/heads/", " ".join(evidence["incomplete_reasons"]))

    def test_malformed_objects_make_the_capture_incomplete(self) -> None:
        def blob(repo: Path) -> str:
            return subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD:src/app.py"], check=True, capture_output=True,
                                  text=True).stdout.strip()

        def truncated_offset_delta(repo: Path) -> None:
            # The pack ends inside the entry's header, before its base offset.
            write_pack(repo / ".git" / "objects" / "pack", [(b"\xab" * 20, bytes([0x60]))], trailer=False)
            point_head_at(repo, "ab" * 20)

        cases = {
            "non-octal tree mode": lambda repo: plant_commit(repo, tree_entry("100648", "app.py", blob(repo))),
            "a mode too large": lambda repo: plant_commit(repo, tree_entry("1100644", "app.py", blob(repo))),
            "a name repeated in one tree": lambda repo: plant_commit(
                repo, tree_entry("100644", "a.py", blob(repo)) + tree_entry("100644", "a.py", blob(repo))),
            "truncated offset delta header": truncated_offset_delta,
        }
        for label, prepare in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                prepare(repo)
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertTrue(evidence["incomplete"])
                self.assertIn("HEAD cannot be read", " ".join(evidence["incomplete_reasons"]))

    def test_tree_modes_are_canonicalized_as_git_prints_them(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            oid = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD:src/app.py"], check=True, capture_output=True,
                                 text=True).stdout.strip()
            plant_commit(repo, tree_entry("100654", "group-exec.sh", oid) + tree_entry("0100644", "padded.txt", oid)
                         + tree_entry("100755", "run.sh", oid))
            evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
            self.assertFalse(evidence.get("error"), evidence.get("incomplete_reasons"))
            self.assertEqual((evidence["head"], evidence["head_manifest_sha256"]), oracle_manifest(repo))

    def test_controller_helpers_never_run_a_promisor_helper(self) -> None:
        variants = (("defaults", ()), ("repository protocol.file.allow", (("protocol.file.allow", "always"),)),
                    ("repository protocol.allow", (("protocol.allow", "always"),)))
        for label, settings in variants:
            with self.subTest(settings=label), tempfile.TemporaryDirectory() as tmpdir:
                base = Path(tmpdir)
                repo = make_repo(base)

                def rev(name: str) -> str:
                    return subprocess.run(["git", "-C", str(repo), "rev-parse", name], check=True, capture_output=True,
                                          text=True).stdout.strip()

                first = rev("HEAD")
                (repo / "src" / "more.py").write_text("print('b')\n", encoding="utf-8")
                git(repo, "add", "-A")
                git(repo, "commit", "-qm", "second")
                blob, tree = rev("HEAD:src/app.py"), rev("HEAD:src")
                for oid in (blob, tree, first):
                    (repo / ".git" / "objects" / oid[:2] / oid[2:]).unlink()
                marker = base / "PROMISOR_RAN"
                git(repo, "config", "extensions.partialClone", "origin")
                git(repo, "config", "remote.origin.promisor", "true")
                git(repo, "config", "remote.origin.url", str(base / "upstream"))
                git(repo, "config", "remote.origin.uploadpack", f"sh -c 'touch {marker}; exit 1' --")
                for key, value in settings:
                    git(repo, "config", key, value)
                helpers = {
                    "show": lambda: workspace_capture.trusted_git_output(repo, ["show", blob]),
                    "ls-tree": lambda: workspace_capture.trusted_git_output(repo, ["ls-tree", "-r", "HEAD"]),
                    "ancestry": lambda: workspace_capture.trusted_git_succeeds(repo, ["merge-base", "--is-ancestor", first, "HEAD"]),
                    "cat-file": lambda: workspace_capture.trusted_git_completed(repo, ["cat-file", "-p", blob]),
                }
                for name, call in helpers.items():
                    try:
                        call()
                    except workspace_capture.WorkspaceDiscoveryError:
                        pass
                    self.assertFalse(marker.exists(), f"{name}: no promisor helper may run")
                # Control: the same Git without the helpers' hardening runs it.
                control = subprocess.run([workspace_capture.trusted_git().path, "-C", str(repo), "cat-file", "-p", blob],
                                         capture_output=True, env={"PATH": "/usr/bin:/bin", "HOME": str(base)})
                self.assertNotEqual(control.returncode, 0)
                self.assertTrue(marker.exists(), "control: plain Git runs the promisor helper")


class WriteRecorder:
    """Records every filesystem call that creates, changes or removes something, by absolute real path."""

    WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND

    def __init__(self) -> None:
        self.paths: list[str] = []

    def _note(self, path: object, dir_fd: int | None) -> None:
        name = os.fsdecode(path)  # type: ignore[arg-type]
        if dir_fd is not None and not os.path.isabs(name):
            name = os.path.join(os.readlink(f"/proc/self/fd/{dir_fd}"), name)
        self.paths.append(os.path.realpath(name))

    def inside(self, directory: Path) -> list[str]:
        top = os.path.realpath(directory)
        return [path for path in self.paths if path == top or path.startswith(top + os.sep)]

    def __enter__(self) -> "WriteRecorder":
        real = {name: getattr(os, name) for name in ("open", "mkdir", "unlink", "remove", "rmdir", "symlink", "rename", "replace")}

        def opening(path: object, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
            if flags & self.WRITE_FLAGS:
                self._note(path, dir_fd)
            return real["open"](path, flags, mode, dir_fd=dir_fd)

        def changing(name: str):
            def call(path: object, *args: object, **kwargs: object) -> object:
                self._note(path if name not in {"symlink"} else args[0], kwargs.get("dir_fd"))  # type: ignore[arg-type]
                return real[name](path, *args, **kwargs)
            return call

        self._patches = [mock.patch.object(os, "open", opening)]
        self._patches += [mock.patch.object(os, name, changing(name)) for name in real if name != "open"]
        for patch in self._patches:
            patch.start()
        return self

    def __exit__(self, *exc: object) -> None:
        for patch in reversed(self._patches):
            patch.stop()


class RoundNineTests(unittest.TestCase):
    """Bounded object allocation, iterative traversal and exact Git parsing."""

    def test_scratch_selection_never_writes_before_it_is_checked(self) -> None:
        for inside in ("tmp", ".git/tmp"):
            with self.subTest(temporary_directory=inside), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                scratch = repo / inside
                scratch.mkdir()
                environment = {"TMPDIR": str(scratch), "TEMP": str(scratch), "TMP": str(scratch)}
                # tempfile has not chosen a directory yet, so gettempdir() would probe the candidates.
                with mock.patch.object(tempfile, "tempdir", None), mock.patch.dict(os.environ, environment), \
                        WriteRecorder() as recorder:
                    state = capture_tracked_workspace_state(repo, include_untracked=True)
                self.assertEqual(recorder.inside(repo), [], "nothing is created, written or removed in the workspace")
                self.assertFalse(state["incomplete"], state.get("incomplete_reasons"))
                self.assertTrue(recorder.paths, "the recorder saw the scratch repository being written elsewhere")
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            (repo / "tmp").mkdir()
            inside = {name: str(repo / "tmp") for name in ("TMPDIR", "TEMP", "TMP")}
            with mock.patch.object(tempfile, "tempdir", None), mock.patch.dict(os.environ, inside), \
                    mock.patch.object(workspace_capture, "SCRATCH_PARENTS", (str(repo), str(repo / ".git"))), \
                    WriteRecorder() as recorder:
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
            self.assertEqual(recorder.inside(repo), [])
            self.assertTrue(evidence["incomplete"])
            self.assertIn("no scratch directory outside", " ".join(evidence["incomplete_reasons"]))

    def test_dishonest_sizes_never_allocate_past_the_declared_size(self) -> None:
        import tracemalloc

        from cwo_core.git_store import CorruptObject, apply_delta

        mebibyte = 1 << 20
        base = b"a" * mebibyte
        cases = {
            # Declares 1 MiB but copies the whole base twice (0xC0 0x10: copy 0x10 << 16 bytes from offset 0).
            "copies": delta_size(mebibyte) + delta_size(mebibyte) + bytes([0xC0, 0x10]) * 2,
            # Declares 1 MiB, copies it, then inserts more.
            "inserts": delta_size(mebibyte) + delta_size(mebibyte) + bytes([0xC0, 0x10]) + b"\x7f" + b"x" * 0x7F,
        }
        for label, delta in cases.items():
            with self.subTest(delta=label):
                tracemalloc.start()
                try:
                    with self.assertRaisesRegex(CorruptObject, "larger than declared"):
                        apply_delta(base, delta, max_size=mebibyte)
                    peak = tracemalloc.get_traced_memory()[1]
                finally:
                    tracemalloc.stop()
                self.assertLess(peak, mebibyte + mebibyte // 4, "nothing beyond the declared result is allocated")

    def test_object_sizes_are_charged_before_anything_is_inflated(self) -> None:
        import tracemalloc
        import zlib

        from cwo_core.git_store import CorruptObject, ObjectStore

        class Spent(Exception):
            pass

        mebibyte = 1 << 20

        def store(objects: Path, budget: int) -> ObjectStore:
            charged: list[int] = []

            def charge(count: int) -> None:
                charged.append(count)
                if sum(charged) > budget:
                    raise Spent

            return ObjectStore(str(objects), hash_name="sha1", open_regular=lambda path: os.open(path, os.O_RDONLY),
                               list_names=os.listdir, charge=charge, check_time=lambda: None, max_object_bytes=16 * mebibyte)

        data = b"z" * (4 * mebibyte)
        with tempfile.TemporaryDirectory() as tmpdir:
            loose = Path(tmpdir) / "loose"
            oid = blob_entry(data)[0]
            (loose / oid[:2]).mkdir(parents=True)
            (loose / oid[:2] / oid[2:]).write_bytes(zlib.compress(b"blob %d\0" % len(data) + data))
            packed = Path(tmpdir) / "packed"
            write_pack(packed / "pack", [(bytes.fromhex(oid), blob_entry(data)[1])])
            for label, objects in (("loose", loose), ("packed", packed)):
                with self.subTest(objects=label):
                    tracemalloc.start()
                    try:
                        with self.assertRaises(Spent):
                            store(objects, mebibyte).read(oid)
                        peak = tracemalloc.get_traced_memory()[1]
                    finally:
                        tracemalloc.stop()
                    self.assertLess(peak, mebibyte, "the 4 MiB object is refused before it is inflated")
                    self.assertEqual(store(objects, 8 * mebibyte).read(oid), ("blob", data))
            # A header that understates the body, and one too long to be a size, are refused.
            for label, raw in (("understated", b"blob 10\0" + b"z" * 100), ("long size", b"blob " + b"9" * 5000 + b"\0")):
                with self.subTest(header=label):
                    planted = Path(tmpdir) / label
                    target = planted / "ab" / ("c" * 38)
                    target.parent.mkdir(parents=True)
                    target.write_bytes(zlib.compress(raw))
                    with self.assertRaises(CorruptObject):
                        store(planted, 8 * mebibyte).read("ab" + "c" * 38)

    def test_reference_names_keep_their_bytes(self) -> None:
        def rev(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)

        branch = "refs/heads/topic\u00a0"
        for sibling_only in (False, True):
            with self.subTest(sibling_only=sibling_only), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                git(repo, "branch", "topic")
                if not sibling_only:
                    git(repo, "checkout", "-q", "-b", "topic\u00a0")
                    (repo / "src" / "only-here.py").write_text("x\n", encoding="utf-8")
                    git(repo, "add", "-A")
                    git(repo, "commit", "-qm", "on the branch with the trailing space")
                (repo / ".git" / "HEAD").write_bytes(f"ref: {branch}\n".encode())
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertFalse(evidence.get("error"), evidence.get("incomplete_reasons"))
                if sibling_only:
                    self.assertNotEqual(rev(repo, "rev-parse", "--verify", "-q", "HEAD").returncode, 0, "Git: unborn")
                    self.assertEqual(evidence["head"], "unborn")
                else:
                    self.assertEqual((evidence["head"], evidence["head_manifest_sha256"]), oracle_manifest(repo))
        for label, content in (("a trailing unit separator", "{oid}\x1c\n"), ("a trailing vertical tab", "{oid}\x0b\n"),
                               ("a leading space", " {oid}\n")):
            with self.subTest(loose_reference=label), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                oid = rev(repo, "rev-parse", "HEAD").stdout.strip()
                reference = (repo / ".git" / "HEAD").read_text(encoding="utf-8").split(":", 1)[1].strip()
                (repo / ".git" / reference).write_text(content.format(oid=oid), encoding="utf-8")
                self.assertNotEqual(rev(repo, "rev-parse", "--verify", "-q", "HEAD").returncode, 0, "Git refuses it too")
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertTrue(evidence["incomplete"])

    def test_every_occurrence_of_a_setting_is_checked(self) -> None:
        cases = {
            "core.bare": "[core]\n\tbare = maybe\n[core]\n\tbare = false\n",
            "core.ignorecase": "[core]\n\tignorecase = maybe\n[core]\n\tignorecase = true\n",
            "extensions.worktreeConfig": "[extensions]\n\tworktreeConfig = maybe\n[extensions]\n\tworktreeConfig = true\n",
            "core.repositoryformatversion": "[core]\n\trepositoryformatversion = junk\n[core]\n\trepositoryformatversion = 0\n",
        }
        for label, text in cases.items():
            with self.subTest(setting=label), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                with (repo / ".git" / "config").open("a", encoding="utf-8") as handle:
                    handle.write(text)
                status = subprocess.run(["git", "-C", str(repo), "status"], capture_output=True)
                self.assertNotEqual(status.returncode, 0, "Git refuses the earlier occurrence")
                with self.assertRaises(workspace_capture.WorkspaceDiscoveryError):
                    workspace_capture.worktree_top_level(repo)
                self.assertTrue(capture_workspace_baseline(repo, allowed_paths=["src"])["incomplete"])

    def test_oversized_numbers_are_refused_through_both_boundaries(self) -> None:
        huge = "1" * 4301
        for key, value in (("core.bare", huge), ("core.ignorecase", huge), ("core.repositoryformatversion", huge),
                           ("core.bare", "0x" + "f" * 5000)):
            with self.subTest(key=key, value=value[:8]), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                git(repo, "config", key, value)
                status = subprocess.run(["git", "-C", str(repo), "status"], capture_output=True)
                self.assertNotEqual(status.returncode, 0, "Git refuses the number too")
                with self.assertRaises(workspace_capture.WorkspaceDiscoveryError):
                    workspace_capture.worktree_top_level(repo)
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertTrue(evidence["incomplete"])

    def test_unexpected_malformed_data_never_escapes_either_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            for error in (ValueError("planted"), IndexError("planted"), RecursionError("planted")):
                with self.subTest(error=type(error).__name__), \
                        mock.patch.object(workspace_capture.git_store, "parse_config", side_effect=error):
                    with self.assertRaises(workspace_capture.WorkspaceDiscoveryError):
                        workspace_capture.worktree_top_level(repo)
                    self.assertTrue(capture_workspace_baseline(repo, allowed_paths=["src"])["incomplete"])

    def test_metadata_cycles_and_deep_trees_are_walked_without_recursion(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            (repo / ".git" / "hooks" / "loop").symlink_to(".", target_is_directory=True)
            evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
            self.assertTrue(evidence["incomplete"])
            self.assertIn("metadata directory cycle", " ".join(evidence["incomplete_reasons"]))
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            deep = repo / ".git" / "info"
            for _ in range(600):
                deep = deep / "d"
                deep.mkdir()
            (deep / "bottom").write_text("x\n", encoding="utf-8")
            evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
            self.assertFalse(evidence["incomplete"], evidence.get("incomplete_reasons"))
            self.assertIn("common:info/" + "d/" * 600 + "bottom", evidence["git_metadata"]["entries"])

    def test_deep_untracked_paths_are_mirrored_without_recursion(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            deep = repo
            for _ in range(1100):
                deep = deep / "d"
                deep.mkdir()
            (deep / "file.txt").write_text("x\n", encoding="utf-8")
            state = capture_tracked_workspace_state(repo, include_untracked=True)
            self.assertFalse(state["incomplete"], state.get("incomplete_reasons"))
            self.assertEqual(sorted(line for line in state["tracked_status"] if line.startswith("?? ")), untracked_status(repo))

    def test_config_syntax_follows_git(self) -> None:
        from cwo_core.git_store import UnsupportedLayout, parse_config

        # Each of these was checked against git config --list on Git 2.35.8 and 2.56.0.
        accepted = {
            b'[core]\n\tx = \ra\n': [("core.x", "a")],
            b'[core]\n\tx = a\r \n': [("core.x", "a")],
            b'[core]\n\r\tx = a\n': [("core.x", "a")],
            b'[remote  "x"]\n\turl = u\n': [("remote.x.url", "u")],
            '[core]\n\tx = a\u00a0\n'.encode(): [("core.x", "a\u00a0")],
        }
        for data, entries in accepted.items():
            with self.subTest(accepted=data):
                self.assertEqual(parse_config(data), entries)
        for data in (b"[core]\n\tbare # comment\n", b"[core]\n\tbare ; comment\n", b"[ core]\n\tbare = true\n",
                     b'[remote "x" ]\n\turl = u\n', "[core]\u00a0\n\tx = a\n".encode()):
            with self.subTest(refused=data), self.assertRaises(UnsupportedLayout):
                parse_config(data)

    def test_attribute_lines_are_split_as_git_splits_them(self) -> None:
        name = "P\u2028"
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            (repo / name).write_text("x\n", encoding="utf-8")
            (repo / ".gitattributes").write_text(f"{name} filter=evil\n", encoding="utf-8")
            git(repo, "add", "-A")
            git(repo, "commit", "-qm", "attributes on a name with a line separator")
            check = subprocess.run(["git", "-C", str(repo), "check-attr", "filter", "--", name], capture_output=True, text=True)
            self.assertIn("filter: evil", check.stdout, "Git applies the filter to that name")
            self.assertFalse(workspace.workspace_is_clean(repo, include_untracked=False))

    def test_git_output_keeps_trailing_non_ascii_spaces(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = Path(tmpdir) / "top\u00a0"
            nested.mkdir()
            subprocess.run(["git", "init", "-q", str(nested)], check=True)
            configure_git_fixture(nested)
            self.assertEqual(workspace_capture.trusted_git_output(nested, ["rev-parse", "--show-toplevel"]), str(nested.resolve()))

    def test_integer_fsmonitor_values_are_booleans_not_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            (repo / "2").write_text("not a hook\n", encoding="utf-8")
            git(repo, "config", "core.fsmonitor", "2")
            evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
            # Round 14: from Git 2.36 an integer is a boolean (a complete capture); Git 2.35 resolves it
            # as a program, so with that trusted Git the capture is incomplete.
            if booleans_name_programs():
                self.assertEqual(evidence["incomplete_reasons"], [FSMONITOR_VERSION_REASON])
            else:
                self.assertFalse(evidence["incomplete"], evidence.get("incomplete_reasons"))
            self.assertFalse([key for key in evidence["git_metadata"]["entries"] if key.startswith("dependency:core.fsmonitor")])


class FailingRealpath:
    """Make ``os.path.realpath`` raise ``error`` when the nearest project caller is one of ``callers``.

    Callers are ``(file name, function name)`` pairs; the resolver helper
    itself is skipped, so the location is the function that asked for the
    resolution, before or after this round's changes.
    """

    FILES = {"workspace_capture.py", "workspace.py", "native_pool_workspace.py"}

    def __init__(self, callers: set[tuple[str, str]], error: BaseException) -> None:
        self.callers = callers
        self.error = error
        self.hits: list[str] = []
        self.real = os.path.realpath

    def __call__(self, path: object, *args: object, **kwargs: object) -> str:
        frame = sys._getframe(1)
        while frame is not None:
            location = (os.path.basename(frame.f_code.co_filename), frame.f_code.co_name)
            if location[0] in self.FILES and location[1] != "_real_path":
                break
            frame = frame.f_back
        if frame is not None and location in self.callers:
            self.hits.append(os.fsdecode(path))  # type: ignore[arg-type]
            raise self.error
        return self.real(path, *args, **kwargs)  # type: ignore[arg-type]


def open_descriptors() -> int:
    return len(os.listdir("/proc/self/fd"))


def private_scratch_parent(base: Path) -> tuple[Path, object]:
    """A dedicated scratch parent as the only candidate, and the patches that make it so."""
    parent = base / "scratch-parent"
    parent.mkdir(mode=0o700)
    environment = {name: str(parent) for name in ("TMPDIR", "TEMP", "TMP")}
    patches = (mock.patch.object(tempfile, "tempdir", None), mock.patch.dict(os.environ, environment),
               mock.patch.object(workspace_capture, "SCRATCH_PARENTS", ()))
    return parent, patches


class RoundTenTests(unittest.TestCase):
    """Descriptor-based scratch cleanup and bounded configuration parsing."""

    REAL_RENAME = staticmethod(os.rename)
    REAL_SYMLINK = staticmethod(os.symlink)

    def test_scratch_parent_replaced_before_creation_redirects_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            inside = repo / "inside"
            inside.mkdir()
            parent, patches = private_scratch_parent(base)
            moved = base / "scratch-parent-moved"
            swapped: list[str] = []
            with patches[0], patches[1], patches[2], WriteRecorder() as recorder:
                recorded_mkdir = os.mkdir

                def swap_then_mkdir(path: object, *args: object, **kwargs: object) -> object:
                    # Between the parent's checks and the creation, the parent's path becomes a
                    # symlink to a directory inside the workspace.
                    if not swapped and os.path.basename(os.fsdecode(path)).startswith("cwo-inspect-"):  # type: ignore[arg-type]
                        self.REAL_RENAME(parent, moved)
                        self.REAL_SYMLINK(inside, parent, target_is_directory=True)
                        swapped.append(os.fsdecode(path))  # type: ignore[arg-type]
                    return recorded_mkdir(path, *args, **kwargs)  # type: ignore[arg-type]

                with mock.patch.object(os, "mkdir", swap_then_mkdir):
                    evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
            self.assertTrue(swapped, "the replacement happened between validation and creation")
            self.assertEqual(recorder.inside(repo), [], "nothing is created, written or removed in the workspace")
            self.assertEqual(list(inside.iterdir()), [])
            self.assertEqual(list(moved.iterdir()), [], "the scratch went to the pinned parent and was removed from it")
            self.assertTrue(evidence["incomplete"])
            self.assertIn("scratch directory was replaced", " ".join(evidence["incomplete_reasons"]))

    def test_scratch_parent_replaced_before_cleanup_removes_nothing_inside(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            inside = repo / "inside"
            inside.mkdir()
            parent, patches = private_scratch_parent(base)
            moved = base / "scratch-parent-moved"
            real_run_git = workspace_capture.run_git
            calls: list[str] = []
            planted: list[Path] = []

            def run_then_swap(git: object, root: object, args: list[str], **kwargs: object) -> object:
                result = real_run_git(git, root, args, **kwargs)  # type: ignore[arg-type]
                calls.append(str(kwargs["git_dir"]))
                if len(calls) == 2:
                    # After the last Git command and before cleanup, the parent's path becomes a
                    # symlink into the workspace, where a directory of the scratch's name waits.
                    name = Path(str(kwargs["git_dir"])).parent.name
                    self.REAL_RENAME(parent, moved)
                    decoy = inside / name / "git"
                    decoy.mkdir(parents=True)
                    (decoy / "HEAD").write_text("planted\n", encoding="utf-8")
                    planted.append(decoy / "HEAD")
                    self.REAL_SYMLINK(inside, parent, target_is_directory=True)
                return result

            with patches[0], patches[1], patches[2], mock.patch.object(workspace_capture, "run_git", run_then_swap):
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
            self.assertEqual(len(calls), 2)
            self.assertTrue(planted)
            self.assertEqual(planted[0].read_text(encoding="utf-8"), "planted\n", "nothing inside the workspace is removed")
            self.assertEqual(list(moved.iterdir()), [], "the scratch is removed through its descriptors")
            self.assertTrue(evidence["incomplete"])
            self.assertIn("scratch directory was replaced", " ".join(evidence["incomplete_reasons"]))

    def test_scratch_is_removed_through_descriptors_after_every_capture(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            deep = repo
            for _ in range(1100):
                deep = deep / "d"
                deep.mkdir()
            (deep / "file.txt").write_text("x\n", encoding="utf-8")
            (repo / "link").symlink_to("src")
            parent, patches = private_scratch_parent(base)
            before = open_descriptors()
            with patches[0], patches[1], patches[2], mock.patch.object(shutil, "rmtree", side_effect=AssertionError):
                state = capture_tracked_workspace_state(repo, include_untracked=True)
            self.assertFalse(state["incomplete"], state.get("incomplete_reasons"))
            self.assertEqual(sorted(line for line in state["tracked_status"] if line.startswith("?? ")), untracked_status(repo))
            self.assertEqual(list(parent.iterdir()), [], "the scratch repository and its deep mirror are removed")
            self.assertEqual(open_descriptors(), before)

    def test_config_entries_are_charged_before_they_are_built(self) -> None:
        import tracemalloc

        from cwo_core.git_store import parse_config

        limit = workspace_capture.METADATA_ENTRIES
        entries = 100_000
        data = b"[x]\n" + b"y\n" * entries  # 200,004 bytes

        class Spent(Exception):
            pass

        charged: list[int] = []

        def charge() -> None:
            charged.append(1)
            if len(charged) > limit:
                raise Spent

        tracemalloc.start()
        try:
            with self.assertRaises(Spent):
                parse_config(data, charge_entry=charge)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertEqual(len(charged), limit + 1, "the parser stops at the first entry past the budget")
        self.assertLess(peak, 4 << 20, "no more than the budgeted entries are built")
        counted: list[int] = []
        self.assertEqual(len(parse_config(data, charge_entry=lambda: counted.append(1))), entries)
        self.assertEqual(len(counted), entries, "every entry is charged exactly once")

        real = workspace_capture.git_store.parse_config
        for boundary in ("discovery", "capture"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                with (repo / ".git" / "config").open("ab") as handle:
                    handle.write(data)
                seen: list[dict[str, object]] = []

                def counting(raw: bytes, **kwargs: object) -> object:
                    budget = getattr(kwargs.get("charge_entry"), "__self__", None)
                    record: dict[str, object] = {"budget": budget, "before": getattr(budget, "entries", None)}
                    seen.append(record)
                    try:
                        return real(raw, **kwargs)  # type: ignore[arg-type]
                    finally:
                        record["after"] = getattr(budget, "entries", None)

                tracemalloc.start()
                try:
                    with mock.patch.object(workspace_capture.git_store, "parse_config", side_effect=counting):
                        if boundary == "discovery":
                            with self.assertRaisesRegex(workspace_capture.WorkspaceDiscoveryError, "entry cap"):
                                workspace_capture.worktree_top_level(repo)
                        else:
                            evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                    peak = tracemalloc.get_traced_memory()[1]
                finally:
                    tracemalloc.stop()
                if boundary == "capture":
                    self.assertTrue(evidence["incomplete"])
                    self.assertEqual(evidence["error_kind"], "budget")
                    self.assertIn("entry cap", " ".join(evidence["incomplete_reasons"]))
                self.assertTrue(seen)
                budget = seen[0]["budget"]
                self.assertIsNotNone(budget, "the config parser is given the metadata entry budget")
                self.assertEqual(budget.max_entries, limit)  # type: ignore[union-attr]
                self.assertEqual(seen[0]["after"], limit + 1, "parsing stopped at the first entry past the budget")
                self.assertLess(peak, 6 << 20)

    def test_config_values_check_the_deadline(self) -> None:
        from cwo_core.git_store import parse_config

        class Late(Exception):
            pass

        calls: list[int] = []

        def check_time() -> None:
            calls.append(1)
            if len(calls) > 1:
                raise Late

        # One entry whose value alone takes many steps to read.
        data = ("[x]\n\ty = " + "x " * 200_000 + "\n").encode()
        with self.assertRaises(Late):
            parse_config(data, check_time=check_time)
        self.assertEqual(len(calls), 2)
        # Both boundaries hand the parser the metadata budget's deadline check, and an expired
        # deadline is refused with the budget classification.
        real = workspace_capture.git_store.parse_config
        for boundary in ("discovery", "capture"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                with (repo / ".git" / "config").open("ab") as handle:
                    handle.write(data)
                checks: list[object] = []

                def expiring(raw: bytes, **kwargs: object) -> object:
                    check = kwargs.get("check_time")
                    checks.append(check)
                    budget = getattr(check, "__self__", None)
                    if budget is not None and budget is getattr(kwargs.get("charge_entry"), "__self__", None):
                        budget.deadline = time.monotonic() - 1  # type: ignore[attr-defined]
                    return real(raw, **kwargs)  # type: ignore[arg-type]

                with mock.patch.object(workspace_capture.git_store, "parse_config", side_effect=expiring):
                    if boundary == "discovery":
                        with self.assertRaisesRegex(workspace_capture.WorkspaceDiscoveryError, "deadline"):
                            workspace_capture.worktree_top_level(repo)
                    else:
                        evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                        self.assertEqual(evidence["error_kind"], "budget")
                        self.assertIn("deadline", " ".join(evidence["incomplete_reasons"]))
                self.assertTrue(checks and checks[0] is not None, "the parser is given the deadline check")

    def test_packed_references_are_charged_before_they_are_built(self) -> None:
        import tracemalloc

        from cwo_core.git_store import packed_references

        limit = workspace_capture.METADATA_ENTRIES
        count = 100_000
        fake = b"".join(b"%s refs/heads/b%06d\n" % (b"a" * 40, number) for number in range(count))

        class Spent(Exception):
            pass

        charged: list[int] = []

        def charge() -> None:
            charged.append(1)
            if len(charged) > limit:
                raise Spent

        tracemalloc.start()
        try:
            with self.assertRaises(Spent):
                packed_references(fake, 20, charge_entry=charge)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertEqual(len(charged), limit + 1)
        self.assertLess(peak, 6 << 20, "no more than the budgeted lines are built")
        counted: list[int] = []
        self.assertEqual(len(packed_references(fake, 20, charge_entry=lambda: counted.append(1))), count)
        self.assertEqual(len(counted), count)

        class Late(Exception):
            pass

        ticks: list[int] = []

        def check_time() -> None:
            ticks.append(1)
            raise Late

        with self.assertRaises(Late):
            packed_references(fake, 20, check_time=check_time)

        real = workspace_capture.git_store.packed_references
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            git(repo, "pack-refs", "--all")
            packed = repo / ".git" / "packed-refs"
            packed.write_bytes(packed.read_bytes() + fake)
            seen: list[dict[str, object]] = []

            def counting(raw: bytes, hash_length: int, **kwargs: object) -> object:
                budget = getattr(kwargs.get("charge_entry"), "__self__", None)
                record: dict[str, object] = {"budget": budget}
                seen.append(record)
                try:
                    return real(raw, hash_length, **kwargs)  # type: ignore[arg-type]
                finally:
                    record["after"] = getattr(budget, "entries", None)

            with mock.patch.object(workspace_capture.git_store, "packed_references", side_effect=counting):
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
            self.assertTrue(evidence["incomplete"])
            self.assertEqual(evidence["error_kind"], "budget")
            self.assertIn("entry cap", " ".join(evidence["incomplete_reasons"]))
            self.assertTrue(seen)
            self.assertIsNotNone(seen[0]["budget"], "packed-refs is read under the metadata entry budget")
            self.assertEqual(seen[0]["after"], limit + 1)

    def test_path_resolution_failures_are_structured_refusals(self) -> None:
        from cwo_core.native_pool_workspace import PoolWorkspaceError, _git_common_dir

        errors = (RecursionError("planted"), ValueError("planted"), OSError(errno.ELOOP, "planted"))
        discovery = {("workspace_capture.py", name) for name in
                     ("_probe", "worktree_top_level", "repository_dirs", "_qualify_repository")}
        for error in errors:
            with tempfile.TemporaryDirectory() as tmpdir:
                base = Path(tmpdir)
                repo = make_repo(base)
                parent, patches = private_scratch_parent(base)
                with self.subTest(location="discovery", error=type(error).__name__):
                    failing = FailingRealpath(discovery, error)
                    with mock.patch("os.path.realpath", failing):
                        for call in (lambda: workspace_capture.worktree_top_level(repo),
                                     lambda: workspace_capture.repository_dirs(repo),
                                     lambda: workspace_capture.trusted_git_output(repo, ["rev-parse", "HEAD"])):
                            with self.assertRaises(workspace_capture.WorkspaceDiscoveryError):
                                call()
                        self.assertEqual(workspace_capture.trusted_git_completed(repo, ["rev-parse", "HEAD"]).returncode, 128)
                        with self.assertRaises(workspace.WorkspaceInspectionError):
                            workspace.worktree_state_digest(repo)
                        with self.assertRaises(PoolWorkspaceError):
                            _git_common_dir(repo)
                    self.assertTrue(failing.hits)
                with self.subTest(location="pool common directory", error=type(error).__name__):
                    failing = FailingRealpath({("native_pool_workspace.py", "_git_common_dir")}, error)
                    with mock.patch("os.path.realpath", failing), self.assertRaises(PoolWorkspaceError):
                        _git_common_dir(repo)
                    self.assertTrue(failing.hits)
                with self.subTest(location="baseline root", error=type(error).__name__):
                    failing = FailingRealpath({("workspace.py", "capture_workspace_baseline")}, error)
                    with mock.patch("os.path.realpath", failing):
                        evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                    self.assertTrue(failing.hits)
                    self.assertTrue(evidence["incomplete"])
                    self.assertIn("cannot be resolved", evidence["error"])
                locations = {
                    "capture top level and directories": {("workspace_capture.py", "_run_bound"), ("workspace_capture.py", "run")},
                    "scratch setup": {("workspace_capture.py", "_scratch_directory")},
                }
                for label, callers in locations.items():
                    with self.subTest(location=label, error=type(error).__name__):
                        failing = FailingRealpath(callers, error)
                        before = open_descriptors()
                        with patches[0], patches[1], patches[2], mock.patch("os.path.realpath", failing):
                            result = workspace_capture.capture(repo, max_files=1000, max_bytes=10_000_000, max_seconds=60,
                                                               max_entries=100_000)
                        self.assertTrue(failing.hits)
                        self.assertFalse(result["complete"])
                        self.assertTrue(result["error"], result)
                        self.assertEqual(open_descriptors(), before, "every descriptor is released")
                        self.assertEqual(list(parent.iterdir()), [], "no scratch directory is left behind")

    def test_scratch_setup_failures_clean_up(self) -> None:
        for error in (RecursionError("planted"), ValueError("planted"), OSError(errno.EIO, "planted")):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as tmpdir:
                base = Path(tmpdir)
                repo = make_repo(base)
                parent, patches = private_scratch_parent(base)
                real_mkdir = os.mkdir
                failed: list[str] = []

                def failing_mkdir(path: object, *args: object, **kwargs: object) -> object:
                    name = os.fsdecode(path)  # type: ignore[arg-type]
                    # The scratch directory exists; creating its gitdir fails.
                    if os.path.basename(name) == "git" and ("dir_fd" in kwargs or "cwo-inspect-" in name):
                        failed.append(name)
                        raise error
                    return real_mkdir(path, *args, **kwargs)  # type: ignore[arg-type]

                before = open_descriptors()
                with patches[0], patches[1], patches[2], mock.patch.object(os, "mkdir", failing_mkdir):
                    result = workspace_capture.capture(repo, max_files=1000, max_bytes=10_000_000, max_seconds=60,
                                                       max_entries=100_000)
                self.assertTrue(failed)
                self.assertFalse(result["complete"])
                self.assertEqual(result["error_kind"], "scratch-unavailable")
                self.assertEqual(open_descriptors(), before)
                self.assertEqual(list(parent.iterdir()), [], "the half-built scratch directory is removed")

    def test_fsmonitor_programs_are_found_as_the_shell_finds_them(self) -> None:
        # Round 13: only boolean values are supported. Every program form Git really runs, the plain
        # program path included, makes the capture incomplete; none is inventoried.
        cases = {
            "single-quoted": ("'src/watch' --", "src/watch"),
            "double-quoted with a space": ('"src/my watch" --', "src/my watch"),
            "escaped space": ("src/my\\ watch --", "src/my watch"),
            "quoted inside a word": ("src/'my watch'", "src/my watch"),
            "unquoted with an argument": ("src/watch --", "src/watch"),
            "unquoted": ("src/watch", "src/watch"),
        }
        for label, (value, program) in cases.items():
            with self.subTest(command=label), tempfile.TemporaryDirectory() as tmpdir:
                base = Path(tmpdir)
                repo = make_repo(base)
                target = repo / program
                marker = base / "hook-ran"
                target.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
                target.chmod(0o755)
                git(repo, "config", "core.fsmonitor", value)
                before = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertTrue(before["incomplete"])
                self.assertIn(FSMONITOR_REASON, before["incomplete_reasons"])
                self.assertFalse([key for key in before["git_metadata"]["entries"] if key.startswith("dependency:core.fsmonitor")])
                target.write_text(f"#!/bin/sh\ntouch '{marker}'\n# planted\n", encoding="utf-8")
                after = capture_workspace_baseline(repo, allowed_paths=["src"])
                report = compare_workspace_baseline(before, after, allowed_paths=["src"])
                self.assertTrue(report["unexpected_mutation_detected"], "a change to the hook program is never taken as scoped")
                # Control: Git runs that program.
                subprocess.run(["git", "-C", str(repo), "status"], capture_output=True)
                self.assertTrue(marker.exists(), "Git runs the program named by the command")

    def test_unresolvable_fsmonitor_commands_make_the_capture_incomplete(self) -> None:
        values = (
            "$(echo src/watch)", "`echo src/watch`", "$WATCH", "${WATCH}", '"src/$WATCH"', '"src/\\$x"',
            "src/watch | cat", "src/watch && true", "src/watch || true", "src/watch; true", "src/watch &",
            "src/watch > out", "src/watch < in", "src/watch 2>&1",
            "src/w*", "src/w?tch", "src/[w]atch", "src/{watch,other}", "(src/watch)", "! src/watch",
            "WATCH=1 src/watch", "watch", "~user/watch", "src/watch ~/x", "src/watch # comment",
            "'src/watch", "src/watch\\", "src/watch\nsrc/other", "   ",
        )
        for value in values:
            with self.subTest(command=value), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                (repo / "src" / "watch").write_text("#!/bin/sh\n", encoding="utf-8")
                git(repo, "config", "core.fsmonitor", value)
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertTrue(evidence["incomplete"])
                self.assertIn(FSMONITOR_REASON, evidence["incomplete_reasons"])

    def test_hook_settings_git_releases_read_differently_make_the_capture_incomplete(self) -> None:
        # Git 2.35 to 2.44 read a raw tab or carriage return between words as a space; 2.45
        # and later keep it (evidence/config-syntax-probe-*.txt).
        for key, text in (("core.hookspath", "[core]\n\thooksPath = src/my\thooks\n"),
                          ("core.fsmonitor", "[core]\n\tfsmonitor = src/watch\r--\n")):
            with self.subTest(setting=key), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                (repo / "src" / "watch").write_text("#!/bin/sh\n", encoding="utf-8")
                with (repo / ".git" / "config").open("a", encoding="utf-8", newline="") as handle:
                    handle.write(text)
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertTrue(evidence["incomplete"])
                self.assertIn(f"{key} holds a tab or carriage return", " ".join(evidence["incomplete_reasons"]))

    def test_record_parsers_never_build_past_their_budget(self) -> None:
        import tracemalloc

        # Attributes: lines and tokens are found one at a time, and the deadline is checked.
        text = "ab\n" * 2_000_000
        tracemalloc.start()
        try:
            self.assertEqual(workspace_capture._conversion_attributes(text), [])
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 1 << 20, "a 6 MB attributes file is not split into millions of strings")

        class Late(Exception):
            pass

        def late() -> None:
            raise Late

        with self.assertRaises(Late):
            workspace_capture._conversion_attributes("* " + "text " * 100_000 + "\n", late)
        # Index records from Git's output are charged before each is sliced or decoded.
        probe = workspace_capture.WorktreeCapture(
            Path("/nonexistent"), scope=workspace_capture.CaptureScope(),
            budget=workspace_capture.Budget.start(max_files=0, max_bytes=0, max_seconds=60, max_entries=1000))
        probe.dirs = ("/nonexistent/.git", "/nonexistent/.git", "/nonexistent")
        probe.snapshot = mock.Mock()
        output = b"".join(b"H 100644 %s 0\tpath%06d\0" % (b"a" * 40, number) for number in range(200_000))
        with mock.patch.object(probe, "_regular_or_absent", return_value=None), \
                mock.patch.object(probe, "_snapshot_config", return_value=""), \
                mock.patch.object(probe, "_git", return_value=output):
            tracemalloc.start()
            try:
                with self.assertRaises(workspace_capture.BudgetExhausted):
                    probe._index()
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
        self.assertEqual(probe.budget.entries, 1001)
        self.assertLess(peak, 1 << 20, "Git's 12 MB answer is not split before its records are charged")


class FailingFstat:
    """Make ``os.fstat`` raise ``error`` once, when the nearest capture or store caller is ``caller``."""

    FILES = {"workspace_capture.py", "git_store.py"}

    def __init__(self, caller: str, error: BaseException) -> None:
        self.caller = caller
        self.error = error
        self.hits: list[int] = []
        self.real = os.fstat

    def __call__(self, fd: int, *args: object, **kwargs: object) -> os.stat_result:
        frame = sys._getframe(1)
        while frame is not None and os.path.basename(frame.f_code.co_filename) not in self.FILES:
            frame = frame.f_back
        if not self.hits and frame is not None and frame.f_code.co_name == self.caller:
            self.hits.append(fd)
            raise self.error
        return self.real(fd, *args, **kwargs)  # type: ignore[arg-type]


class CountingScandir:
    """Count every entry ``os.scandir`` yields."""

    def __init__(self) -> None:
        self.visits = 0
        self.real = os.scandir

    def __call__(self, path: object = ".") -> object:
        counter = self
        listing = self.real(path)  # type: ignore[arg-type]

        class Counted:
            def __enter__(self) -> "Counted":
                listing.__enter__()
                return self

            def __exit__(self, *exc: object) -> object:
                return listing.__exit__(*exc)

            def __iter__(self):  # type: ignore[no-untyped-def]
                for entry in listing:
                    counter.visits += 1
                    yield entry

        return Counted()


def descriptor_closed(fd: int) -> bool:
    try:
        os.fstat(fd)
    except OSError as exc:
        return exc.errno == errno.EBADF
    return False


class RoundElevenTests(unittest.TestCase):
    """Scratch relocation, parser budgets and descriptor failure cleanup."""

    REAL_RENAME = staticmethod(os.rename)
    REAL_SYMLINK = staticmethod(os.symlink)
    REAL_UNLINK = staticmethod(os.unlink)

    def test_scratch_parent_moved_into_the_workspace_before_creation_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            inside = repo / "inside"
            inside.mkdir()
            parent, patches = private_scratch_parent(base)
            moved = inside / "scratch-parent"
            real_pin = workspace_capture._pin_directory

            def pin_then_move(path: str) -> object:
                # After the parent is pinned and checked, a writer moves it into the workspace.
                pinned = real_pin(path)
                if pinned is not None and os.path.realpath(path) == os.path.realpath(parent):
                    self.REAL_RENAME(parent, moved)
                return pinned

            with patches[0], patches[1], patches[2], WriteRecorder() as recorder, \
                    mock.patch.object(workspace_capture, "_pin_directory", pin_then_move):
                result = workspace_capture.capture(repo, max_files=1000, max_bytes=10_000_000, max_seconds=60,
                                                   max_entries=100_000)
            self.assertTrue(moved.is_dir(), "the parent was moved into the workspace")
            self.assertEqual(recorder.inside(repo), [], "nothing is created, written or removed in the workspace")
            self.assertEqual(list(moved.iterdir()), [])
            self.assertFalse(result["complete"])
            self.assertEqual(result["error_kind"], "scratch-relocated")
            self.assertIn("relocated into the workspace", result["error"])

    def test_scratch_moved_into_the_workspace_at_creation_is_abandoned(self) -> None:
        # The window between the checkpoint and mkdir remains: one directory is created inside the
        # workspace. The next checkpoint sees it; nothing is written into it, nothing is removed,
        # and its path is reported.
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            inside = repo / "inside"
            inside.mkdir()
            parent, patches = private_scratch_parent(base)
            moved = inside / "scratch-parent"
            swapped: list[str] = []
            with patches[0], patches[1], patches[2], WriteRecorder() as recorder:
                recorded_mkdir = os.mkdir

                def move_then_mkdir(path: object, *args: object, **kwargs: object) -> object:
                    name = os.path.basename(os.fsdecode(path))  # type: ignore[arg-type]
                    if not swapped and name.startswith("cwo-inspect-"):
                        self.REAL_RENAME(parent, moved)
                        swapped.append(name)
                    return recorded_mkdir(path, *args, **kwargs)  # type: ignore[arg-type]

                with mock.patch.object(os, "mkdir", move_then_mkdir):
                    result = workspace_capture.capture(repo, max_files=1000, max_bytes=10_000_000, max_seconds=60,
                                                       max_entries=100_000)
            self.assertTrue(swapped)
            scratch = moved / swapped[0]
            self.assertEqual(recorder.inside(repo), [os.path.realpath(scratch)], "only the racing mkdir landed inside")
            self.assertTrue(scratch.is_dir(), "the abandoned directory is not removed")
            self.assertEqual(list(scratch.iterdir()), [], "nothing is written into it")
            self.assertFalse(result["complete"])
            self.assertEqual(result["error_kind"], "scratch-relocated")
            self.assertEqual(os.path.realpath(result["scratch_abandoned"]), os.path.realpath(scratch))
            reasons = " ".join(result["incomplete_reasons"])
            self.assertIn("relocated into the workspace", reasons)
            self.assertIn("abandoned", reasons)
            self.assertIn(str(os.path.realpath(scratch)), reasons)

    def test_scratch_moved_between_writes_is_abandoned(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            inside = repo / "inside"
            inside.mkdir()
            parent, patches = private_scratch_parent(base)
            moved = inside / "scratch-parent"
            real_write = workspace_capture._Snapshot.write
            names: list[str] = []

            def move_then_write(snapshot: object, name: str, data: bytes) -> None:
                names.append(name)
                if name == "index":
                    self.REAL_RENAME(parent, moved)
                real_write(snapshot, name, data)  # type: ignore[arg-type]

            with patches[0], patches[1], patches[2], WriteRecorder() as recorder, \
                    mock.patch.object(workspace_capture._Snapshot, "write", move_then_write):
                result = workspace_capture.capture(repo, max_files=1000, max_bytes=10_000_000, max_seconds=60,
                                                   max_entries=100_000)
            self.assertIn("index", names)
            self.assertEqual(recorder.inside(repo), [], "nothing is written or removed after the move")
            left = list(moved.iterdir())
            self.assertEqual(len(left), 1, "the scratch directory is abandoned where it now lies")
            self.assertTrue((left[0] / "git" / "HEAD").is_file(), "nothing in it is removed")
            self.assertFalse((left[0] / "git" / "index").exists(), "the write after the move never happens")
            self.assertFalse(result["complete"])
            self.assertEqual(result["error_kind"], "scratch-relocated")
            self.assertEqual(os.path.realpath(result["scratch_abandoned"]), os.path.realpath(left[0]))
            self.assertIn("abandoned", " ".join(result["incomplete_reasons"]))

    def test_replacement_restored_around_git_is_detected(self) -> None:
        for target in ("pinned parent", "scratch gitdir"):
            with self.subTest(replaced=target), tempfile.TemporaryDirectory() as tmpdir:
                base = Path(tmpdir)
                repo = make_repo(base)
                inside = repo / "inside"
                inside.mkdir()
                parent, patches = private_scratch_parent(base)
                real_run_git = workspace_capture.run_git
                swaps: list[Path] = []

                def replace_run_restore(git: object, root: object, args: list[str], **kwargs: object) -> object:
                    if swaps:
                        return real_run_git(git, root, args, **kwargs)  # type: ignore[arg-type]
                    # After the checks before Git, the path Git takes is replaced by a symlink to a
                    # copy inside the workspace; Git runs there; the original is restored before
                    # the checks after Git.
                    victim = parent if target == "pinned parent" else Path(str(kwargs["git_dir"]))
                    away = victim.with_name(victim.name + ".away")
                    decoy = inside / "decoy"
                    self.REAL_RENAME(victim, away)
                    shutil.copytree(away, decoy, symlinks=True)
                    self.REAL_SYMLINK(decoy, victim, target_is_directory=True)
                    swaps.append(decoy)
                    try:
                        return real_run_git(git, root, args, **kwargs)  # type: ignore[arg-type]
                    finally:
                        self.REAL_UNLINK(victim)
                        self.REAL_RENAME(away, victim)

                with patches[0], patches[1], patches[2], mock.patch.object(workspace_capture, "run_git", replace_run_restore):
                    result = workspace_capture.capture(repo, max_files=1000, max_bytes=10_000_000, max_seconds=60,
                                                       max_entries=100_000)
                self.assertTrue(swaps, "Git ran on the replacement")
                self.assertFalse(result["complete"])
                self.assertIn("replaced or changed while Git ran", result["error"])
                self.assertNotIn("scratch_abandoned", result, "the scratch never left its pinned location")
                self.assertEqual(list(parent.iterdir()), [], "the scratch is removed through its descriptors")

    def test_fsmonitor_arguments_are_charged_before_they_are_built(self) -> None:
        import tracemalloc

        def probe(value: str) -> workspace_capture.WorktreeCapture:
            capture = workspace_capture.WorktreeCapture(
                Path("/workspace"), scope=workspace_capture.CaptureScope(),
                budget=workspace_capture.Budget.start(max_files=0, max_bytes=0, max_seconds=60, max_entries=0))
            capture.state = workspace_capture._State()
            capture.dependencies, capture.config_files, capture.conversion_sources = {}, set(), set()
            capture.config_entries = {"/workspace/.git/config": [("core.fsmonitor", value)]}
            return capture

        # Round 13: a value that is not a boolean is refused as a program. Neither 2,000 nor 30,000
        # arguments are tokenized, charged or recorded; the capture is incomplete.
        for count in (2_000, 30_000):
            refused = probe("src/watch.sh" + " a" * count)
            tracemalloc.start()
            try:
                refused._config()
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
            self.assertEqual(refused.dependencies, {})
            self.assertEqual(refused.meta_budget.entries, 0, "nothing is built, so nothing is charged")
            self.assertEqual(refused.state.reasons, [FSMONITOR_REASON])
            self.assertLess(peak, 2 << 20, "at most 2 MiB, against about 1.8 GB in round 10")
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            git(repo, "config", "core.fsmonitor", "src/watch.sh" + " a" * 30_000)
            evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
            self.assertTrue(evidence["incomplete"])
            self.assertIn(FSMONITOR_REASON, evidence["incomplete_reasons"])

    def test_interpreter_fsmonitor_commands_are_refused(self) -> None:
        values = (
            "/bin/sh -c 'exec src/watch' --",
            "/usr/bin/python3 -c 'import os; os.system(\"src/watch\")'",
            "/usr/bin/python3 src/watch.py",
            "/usr/bin/python3.12 src/watch.py",
            "/usr/bin/env src/watch",
            "./bin/bash src/watch",
            "/usr/bin/perl -e 1",
            "/usr/local/bin/node src/watch.js",
            "src/mysh -c 'exec src/watch'",
        )
        for value in values:
            with self.subTest(command=value), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                (repo / "src" / "watch").write_text("#!/bin/sh\n", encoding="utf-8")
                git(repo, "config", "core.fsmonitor", value)
                before = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertTrue(before["incomplete"])
                self.assertIn(FSMONITOR_REASON, before["incomplete_reasons"])
                # The reviewer's probe: a change to the script the shell runs is never taken as scoped.
                (repo / "src" / "watch").write_text("#!/bin/sh\n# planted\n", encoding="utf-8")
                after = capture_workspace_baseline(repo, allowed_paths=["src"])
                report = compare_workspace_baseline(before, after, allowed_paths=["src"])
                self.assertTrue(report["unexpected_mutation_detected"], report)

    def test_config_names_are_bounded_before_they_are_built(self) -> None:
        import tracemalloc

        from cwo_core.git_store import UnsupportedLayout, parse_config

        data = ('[x "' + "s" * 65_536 + '"]\n').encode() + b"".join(b"\tk%d = v\n" % number for number in range(1_000))
        tracemalloc.start()
        try:
            with self.assertRaisesRegex(UnsupportedLayout, "names would exceed"):
                parse_config(data)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 6 << 20, "at most 6 MiB, against about 66 MB before")
        charged: list[int] = []
        with self.assertRaises(UnsupportedLayout):
            parse_config(data, charge_bytes=charged.append)
        self.assertTrue(charged and all(size > 65_536 for size in charged), "each name's size is charged before it is built")
        self.assertLessEqual(sum(charged), workspace_capture.git_store.CONFIG_NAME_CHARACTERS)
        # A subsection made of escapes is read in bounded steps too.
        escaped = ('[x "' + "\\a" * 32_768 + '"]\n').encode() + b"".join(b"\tk%d = v\n" % number for number in range(1_000))
        tracemalloc.start()
        try:
            with self.assertRaisesRegex(UnsupportedLayout, "names would exceed"):
                parse_config(escaped)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 6 << 20)
        # Ordinary names are untouched.
        self.assertEqual(parse_config(b'[remote "origin"]\n\turl = x\n'), [("remote.origin.url", "x")])
        for boundary in ("discovery", "capture"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                with (repo / ".git" / "config").open("ab") as handle:
                    handle.write(data)
                if boundary == "discovery":
                    with self.assertRaisesRegex(workspace_capture.WorkspaceDiscoveryError, "names would exceed"):
                        workspace_capture.worktree_top_level(repo)
                else:
                    evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                    self.assertTrue(evidence["incomplete"])
                    self.assertIn("names would exceed", evidence["error"])

    def test_section_headers_are_read_as_git_reads_them(self) -> None:
        from cwo_core.git_store import UnsupportedLayout, parse_config

        # Git 2.35.8 and 2.56.0 read these the same way (evidence/config-syntax-probe-*.txt).
        accepted = {
            b'[remote "a\\"b"]': "remote.a\"b.url",
            b'[remote "a\\\\b"]': "remote.a\\b.url",
            b'[remote "a\\xb"]': "remote.axb.url",
            b'[remote "a b"]': "remote.a b.url",
            b'[remote "a]b"]': "remote.a]b.url",
            b'[remote ""]': "remote..url",
            b'[Remote "AbC"]': "remote.AbC.url",
            b'[remote "a"] # c': "remote.a.url",
            b'[remote "a"]\t; c': "remote.a.url",
            b'[remote\t"a"]': "remote.a.url",
            b'[remote\r"a"]': "remote.a.url",
        }
        for header, name in accepted.items():
            with self.subTest(header=header):
                self.assertEqual(parse_config(header + b"\n\tURL = u\n"), [(name, "u")])
        # Git rejects all but the first (a key after the header, which Git accepts and this reader refuses).
        for header in (b'[remote "a"]x', b'[remote "a\nb"]', b'[remote "a\\\nb"]', b'[remote "a"', b'[remote "a" ]'):
            with self.subTest(header=header), self.assertRaises(UnsupportedLayout):
                parse_config(header + b"\n\turl = u\n")

    def test_comment_and_blank_attribute_lines_check_the_deadline(self) -> None:
        class Late(Exception):
            pass

        for label, text in (("comments", "# c\n" * 200_000), ("blank lines", "\n" * 200_000), ("blank words", " \t\n" * 200_000)):
            with self.subTest(lines=label):
                calls: list[int] = []

                def expired() -> None:
                    calls.append(1)
                    raise Late

                with self.assertRaises(Late):
                    workspace_capture._conversion_attributes(text, expired)
                self.assertTrue(calls, "the deadline callback is called")
        self.assertEqual(workspace_capture._conversion_attributes("# c\n\n* text\n", lambda: None), ["text"])
        # The deadline is checked before conversion scanning's answer becomes evidence.
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            (repo / ".gitattributes").write_text("# nothing\n", encoding="utf-8")
            scanned: list[int] = []

            def expiring(text: str, check_time: object = None) -> list[str]:
                scanned.append(1)
                getattr(check_time, "__self__").deadline = time.monotonic() - 1
                return []

            with mock.patch.object(workspace_capture, "_conversion_attributes", expiring):
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
            self.assertTrue(scanned)
            self.assertTrue(evidence["incomplete"])
            self.assertEqual(evidence["error_kind"], "budget")
            self.assertIn("deadline", evidence["error"])

    def test_pack_descriptors_are_closed_when_reading_the_index_fails(self) -> None:
        from cwo_core.git_store import ObjectStore

        for seam in ("pread", "fstat"):
            with self.subTest(failing=seam), tempfile.TemporaryDirectory() as tmpdir:
                objects = Path(tmpdir) / "objects"
                oid, raw = blob_entry(b"packed\n")
                write_pack(objects / "pack", [(bytes.fromhex(oid), raw)])
                opened: list[int] = []

                def open_regular(path: str) -> int:
                    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
                    opened.append(fd)
                    return fd

                store = ObjectStore(str(objects), hash_name="sha1", open_regular=open_regular, list_names=os.listdir,
                                    charge=lambda size: None, check_time=lambda: None, max_object_bytes=1 << 20)
                real_pread = os.pread
                real_fstat = os.fstat

                def failing_pread(fd: int, *args: object) -> bytes:
                    if fd in opened:
                        raise OSError(errno.EIO, "planted")
                    return real_pread(fd, *args)  # type: ignore[arg-type]

                def failing_fstat(fd: int, *args: object, **kwargs: object) -> os.stat_result:
                    if fd in opened:
                        raise OSError(errno.EIO, "planted")
                    return real_fstat(fd, *args, **kwargs)  # type: ignore[arg-type]

                patch = mock.patch.object(os, "pread", failing_pread) if seam == "pread" else \
                    mock.patch.object(os, "fstat", failing_fstat)
                try:
                    with patch, self.assertRaises(OSError):
                        store.read(oid)
                    self.assertEqual(len(opened), 2, "the index and the pack were opened")
                    store.close()
                    self.assertTrue(all(descriptor_closed(fd) for fd in opened), "both descriptors are closed")
                finally:
                    for fd in opened:
                        if not descriptor_closed(fd):
                            os.close(fd)

    def test_cleanup_lists_each_directory_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            top = Path(tmpdir) / "top"
            top.mkdir()
            for number in range(1_000):
                child = top / f"d{number:04d}"
                child.mkdir()
                (child / "f").write_bytes(b"")
            counter = CountingScandir()
            fd = os.open(top, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(os, "scandir", counter):
                    workspace_capture._empty_directory(fd)
            finally:
                os.close(fd)
            self.assertEqual(list(top.iterdir()), [])
            # 2,000 entries: each is listed once, against 500,500 visits for the children alone before.
            self.assertLessEqual(counter.visits, 2_000)

    def test_cleanup_past_its_deadline_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            parent, patches = private_scratch_parent(base)
            before = open_descriptors()
            with patches[0], patches[1], patches[2], mock.patch.object(workspace_capture, "CLEANUP_GRACE_SECONDS", -3600.0):
                result = workspace_capture.capture(repo, max_files=1000, max_bytes=10_000_000, max_seconds=60,
                                                   max_entries=100_000)
            self.assertEqual(open_descriptors(), before)
            left = list(parent.iterdir())
            self.assertEqual(len(left), 1, "the cleanup stopped and left the directory")
            self.assertFalse(result["complete"])
            self.assertIsNone(result["error"], "the capture itself succeeded")
            self.assertFalse(result["metadata"]["complete"])
            self.assertIn("scratch cleanup stopped at its deadline", " ".join(result["incomplete_reasons"]))
            self.assertEqual(os.path.realpath(result["scratch_abandoned"]), os.path.realpath(left[0]))

    def test_descriptors_are_released_when_fstat_fails(self) -> None:
        # Sweep: a directory opened during the walk, the metadata snapshot or scratch creation was
        # leaked when the fstat that confirms it failed.
        for caller, kind in (("_walk", "io-failed"), ("_snapshot_entry", "io-failed"),
                             ("_create_private_directory", "scratch-unavailable")):
            with self.subTest(caller=caller), tempfile.TemporaryDirectory() as tmpdir:
                base = Path(tmpdir)
                repo = make_repo(base)
                parent, patches = private_scratch_parent(base)
                failing = FailingFstat(caller, OSError(errno.EIO, "planted"))
                before = open_descriptors()
                with patches[0], patches[1], patches[2], mock.patch.object(os, "fstat", failing):
                    result = workspace_capture.capture(repo, max_files=1000, max_bytes=10_000_000, max_seconds=60,
                                                       max_entries=100_000)
                self.assertTrue(failing.hits)
                self.assertFalse(result["complete"])
                self.assertEqual(result["error_kind"], kind, result)
                self.assertEqual(open_descriptors(), before, "every descriptor is released")
                self.assertEqual(list(parent.iterdir()), [], "no scratch directory is left behind")


def deep_tree(base: Path, levels: int, leaves: int, name_length: int = 255, leaf_name: str = "f{:04d}") -> str:
    """A tree ``levels`` directories deep, each named by ``name_length`` characters, over ``leaves`` files."""
    blob = write_loose(base, "blob", b"leaf\n")
    tree = write_loose(base, "tree", b"".join(tree_entry("100644", leaf_name.format(n), blob) for n in range(leaves)))
    for level in range(levels):
        tree = write_loose(base, "tree", tree_entry("40000", f"{level:03d}".ljust(name_length, "d"), tree))
    return tree


class FailingFrom:
    """Make ``os.<function>`` raise ``error`` on the ``nth`` call whose nearest capture caller is ``caller``."""

    def __init__(self, function: str, caller: str, error: BaseException, nth: int = 1,
                 before: object = None) -> None:
        self.real = getattr(os, function)
        self.caller = caller
        self.error = error
        self.nth = nth
        self.before = before
        self.calls = 0
        self.results: list[object] = []

    def __call__(self, *args: object, **kwargs: object) -> object:
        frame = sys._getframe(1)
        while frame is not None and os.path.basename(frame.f_code.co_filename) not in {"workspace_capture.py", "git_store.py"}:
            frame = frame.f_back
        if frame is not None and frame.f_code.co_name == self.caller:
            self.calls += 1
            if self.calls == self.nth:
                if callable(self.before):
                    self.before()
                raise self.error
            result = self.real(*args, **kwargs)
            self.results.append(result)
            return result
        return self.real(*args, **kwargs)


class RoundTwelveTests(unittest.TestCase):
    """Tree-path budgets, deadlines and filesystem monitor restrictions."""

    REAL_RENAME = staticmethod(os.rename)

    # Defect 1: expanded tree paths ----------------------------------------------------

    def test_tree_paths_are_charged_before_they_are_built(self) -> None:
        import tracemalloc

        from cwo_core.git_store import ObjectStore

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            objects = base / ".git" / "objects"
            objects.mkdir(parents=True)
            # The reviewer's case: 300 levels of 255-byte names over 1,000 leaves, about 116 KB of
            # objects and 1,300 entries, expanding to about 77 MB of paths.
            top = deep_tree(base, 300, 1_000)
            object_bytes: list[int] = []
            store = ObjectStore(str(objects), hash_name="sha1", open_regular=lambda path: os.open(path, os.O_RDONLY | os.O_CLOEXEC),
                                list_names=os.listdir, charge=object_bytes.append, check_time=lambda: None,
                                max_object_bytes=1 << 20)
            charged: list[int] = []
            cap = 4 << 20

            def charge_bytes(count: int) -> None:
                charged.append(count)
                if sum(charged) > cap:
                    raise workspace_capture.BudgetExhausted("byte cap")

            with self.subTest(part="the reviewer's tree, directly"):
                tracemalloc.start()
                try:
                    with self.assertRaisesRegex(workspace_capture.BudgetExhausted, "byte cap"):
                        store.tree_manifest(top, lambda: None, charge_bytes)
                    peak = tracemalloc.get_traced_memory()[1]
                finally:
                    tracemalloc.stop()
                    store.close()
                self.assertLess(sum(object_bytes), 200_000, "the objects themselves are small")
                self.assertLess(peak, 8 << 20, "allocation stays within the charged budget (about 77 MB before)")

            # Exact accounting: every directory prefix and path is charged its length times its
            # character width, before it is built.
            for label, leaf, width in (("ascii", "f{:04d}", 1), ("two-byte", "€{:04d}", 2), ("four-byte", "\U0001F600{:04d}", 4)):
                with self.subTest(names=label):
                    small = deep_tree(base, 3, 2, name_length=10, leaf_name=leaf)
                    counted: list[int] = []
                    store = ObjectStore(str(objects), hash_name="sha1", open_regular=lambda path: os.open(path, os.O_RDONLY | os.O_CLOEXEC),
                                        list_names=os.listdir, charge=lambda size: None, check_time=lambda: None,
                                        max_object_bytes=1 << 20)
                    try:
                        manifest = store.tree_manifest(small, lambda: None, counted.append)
                    finally:
                        store.close()
                    directories = 11 + 22 + 33
                    leaves = sum(len(path) for path in manifest) * width
                    self.assertEqual(len(manifest), 2)
                    self.assertEqual(sum(counted), directories + leaves)

        # Through capture: HEAD is the reviewer's tree, and the metadata byte budget refuses it.
        with self.subTest(part="through capture"), tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            top = deep_tree(repo, 300, 1_000)
            commit = write_loose(repo, "commit", f"tree {top}\nauthor t <t@example.invalid> 0 +0000\n"
                                                 f"committer t <t@example.invalid> 0 +0000\n\ndeep\n".encode())
            point_head_at(repo, commit)
            result = workspace_capture.capture(repo, max_files=1000, max_bytes=10_000_000, max_seconds=120,
                                               max_entries=100_000)
            self.assertFalse(result["complete"])
            self.assertEqual(result["error_kind"], "budget", result.get("error"))
            self.assertIn("byte cap", result["error"])

    # Defect 2: deadline inside mark collection --------------------------------------------

    def test_mark_collection_checks_the_deadline_within_a_directory(self) -> None:
        class Late(Exception):
            pass

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            parent, patches = private_scratch_parent(base)
            with patches[0], patches[1], patches[2]:
                snapshot = workspace_capture._Snapshot((str(repo), str(repo / ".git"), str(repo / ".git")))
                try:
                    snapshot.setup()
                    for number in range(10_000):
                        os.close(os.open(f"e{number:05d}", os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC, 0o600,
                                         dir_fd=snapshot.mirror_fd))
                    snapshot.created += 10_000
                    snapshot.check_time = None
                    snapshot.marks()  # control: within the deadline the marks are taken

                    # Expiring once the large directory is being listed: refused within one interval.
                    with self.subTest(deadline="passes while listing"):
                        counter = CountingScandir()

                        def expiring() -> None:
                            if counter.visits > 20:
                                raise Late

                        snapshot.check_time = expiring
                        with mock.patch.object(os, "scandir", counter), self.assertRaises(Late):
                            snapshot.marks()
                        self.assertLessEqual(counter.visits, 20 + workspace_capture.git_store.TIME_CHECK_INTERVAL,
                                             "a bounded number of entries is processed (10,000 before)")

                    # Already expired: refused before anything is listed.
                    with self.subTest(deadline="already passed"):
                        counter = CountingScandir()

                        def expired() -> None:
                            raise Late

                        snapshot.check_time = expired
                        with mock.patch.object(os, "scandir", counter), self.assertRaises(Late):
                            snapshot.marks()
                        self.assertEqual(counter.visits, 0, "the deadline is checked before scanning")
                finally:
                    snapshot.close()
            self.assertEqual(list(parent.iterdir()), [])

    def test_deadline_is_checked_again_before_git_starts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            parent, patches = private_scratch_parent(base)
            real_before = workspace_capture._Snapshot.before_git
            launched: list[list[str]] = []
            real_run_git = workspace_capture.run_git

            def slow_marks(snapshot: object) -> object:
                marks = real_before(snapshot)  # type: ignore[arg-type]
                # The marks took the rest of the time.
                snapshot.check_time.__self__.deadline = time.monotonic() - 1  # type: ignore[attr-defined]
                return marks

            def recording(git: object, root: object, args: list[str], **kwargs: object) -> object:
                launched.append(args)
                return real_run_git(git, root, args, **kwargs)  # type: ignore[arg-type]

            with patches[0], patches[1], patches[2], mock.patch.object(workspace_capture._Snapshot, "before_git", slow_marks), \
                    mock.patch.object(workspace_capture, "run_git", recording):
                result = workspace_capture.capture(repo, max_files=1000, max_bytes=10_000_000, max_seconds=60,
                                                   max_entries=100_000)
            self.assertEqual(launched, [], "Git is not started after the deadline")
            self.assertFalse(result["complete"])
            self.assertEqual(result["error_kind"], "budget")
            self.assertEqual(list(parent.iterdir()), [], "the scratch directory is still removed")

    # Defect 3: fsmonitor allowlist ---------------------------------------------------

    @staticmethod
    def set_fsmonitor(repo: Path, value: str) -> None:
        if value.startswith("-"):
            # Written directly, so no git config release reads the value as an option.
            with (repo / ".git" / "config").open("a", encoding="utf-8") as handle:
                handle.write(f"[core]\n\tfsmonitor = {value}\n")
        else:
            git(repo, "config", "core.fsmonitor", value)

    def test_fsmonitor_values_outside_the_allowlist_make_the_capture_incomplete(self) -> None:
        values = (
            "src/runner -uc 'exec src/watch' --",
            "src/watch --config=src/hook.conf",
            "src/watch --config src/hook.conf",
            "--config=src/hook.conf",
            "-src/watch",
            "src/runner -u -c src/watch",
            "/usr/bin/python3 -uc 'import os'",
            "/usr/bin/python3 src/watch",
            "src/watch -- 2",
            "src/watch --",
            "'src/watch'",
            '"src/watch"',
            "src/wat\\ch",
            "src/my\\ watch",
            "src/$WATCH",
            "$(src/watch)",
            "src/watch;true",
            "src/w*",
            "src/w=atch",
            "~/watch",
            "%(prefix)/watch",
            "watch",
            "src/" + "w" * 4_096,
        )
        for value in values:
            with self.subTest(command=value[:60]), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                (repo / "src" / "watch").write_text("#!/bin/sh\n", encoding="utf-8")
                (repo / "src" / "runner").write_text("#!/bin/sh\n", encoding="utf-8")
                self.set_fsmonitor(repo, value)
                before = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertTrue(before["incomplete"])
                self.assertIn(FSMONITOR_REASON, before["incomplete_reasons"])
                self.assertFalse([key for key in before["git_metadata"]["entries"] if key.startswith("dependency:core.fsmonitor")],
                                 "nothing outside the allowlist is inventoried as a dependency")
                # The reviewer's probe: a change to the script a runner would run is never taken as scoped.
                (repo / "src" / "watch").write_text("#!/bin/sh\n# planted\n", encoding="utf-8")
                after = capture_workspace_baseline(repo, allowed_paths=["src"])
                report = compare_workspace_baseline(before, after, allowed_paths=["src"])
                self.assertTrue(report["unexpected_mutation_detected"], report)

    def test_fsmonitor_allowlist_inventories_one_program_path(self) -> None:
        # Round 13: the program-path form is no longer supported. A relative, an absolute and a
        # .git/hooks program path each make the capture incomplete, and none is inventoried.
        for form in ("relative", "absolute", "hooks"):
            with self.subTest(form=form), tempfile.TemporaryDirectory() as tmpdir:
                base = Path(tmpdir)
                repo = make_repo(base)
                program = {"relative": repo / "src" / "watch", "absolute": base / "hook",
                           "hooks": repo / ".git" / "hooks" / "fsmonitor-watchman"}[form]
                value = {"relative": "src/watch", "absolute": str(program), "hooks": ".git/hooks/fsmonitor-watchman"}[form]
                program.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
                program.chmod(0o755)
                git(repo, "config", "core.fsmonitor", value)
                before = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertTrue(before["incomplete"])
                self.assertIn(FSMONITOR_REASON, before["incomplete_reasons"])
                self.assertNotIn(f"dependency:core.fsmonitor:{value}", before["git_metadata"]["entries"])
                program.write_text("#!/bin/sh\nexit 1\n# planted\n", encoding="utf-8")
                after = capture_workspace_baseline(repo, allowed_paths=["src"])
                report = compare_workspace_baseline(before, after, allowed_paths=["src"])
                self.assertTrue(report["unexpected_mutation_detected"], "a change to the hook program is never taken as clean")

    def test_inspection_never_runs_or_enables_fsmonitor(self) -> None:
        for form in ("relative", "absolute", "boolean"):
            with self.subTest(form=form), tempfile.TemporaryDirectory() as tmpdir:
                base = Path(tmpdir)
                repo = make_repo(base)
                marker = base / "fsmonitor-ran"
                program = repo / "src" / "watch" if form == "relative" else base / "hook"
                value = {"relative": "src/watch", "absolute": str(program), "boolean": "true"}[form]
                program.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n", encoding="utf-8")
                program.chmod(0o755)
                git(repo, "config", "core.fsmonitor", value)
                # A modified tracked file, where git status would consult the monitor.
                (repo / "src" / "app.py").write_text("print('b')\n", encoding="utf-8")
                launched: list[tuple[list[str], dict[str, str]]] = []
                real_popen = subprocess.Popen

                def recording(args: object, *rest: object, **kwargs: object) -> object:
                    launched.append(([os.fsdecode(arg) for arg in args], dict(kwargs.get("env") or {})))  # type: ignore[union-attr, arg-type]
                    return real_popen(args, *rest, **kwargs)  # type: ignore[arg-type, call-overload]

                configs: list[bytes] = []
                real_write = workspace_capture._Snapshot.write

                def write(snapshot: object, name: str, data: bytes) -> None:
                    if name == "config":
                        configs.append(data)
                    real_write(snapshot, name, data)  # type: ignore[arg-type]

                with mock.patch.object(subprocess, "Popen", recording), \
                        mock.patch.object(workspace_capture._Snapshot, "write", write):
                    result = workspace_capture.capture(repo, max_files=1000, max_bytes=10_000_000, max_seconds=60,
                                                       max_entries=100_000)
                # Round 13: a program makes the capture incomplete and a boolean is a complete capture;
                # neither is inventoried, and neither runs or enables the monitor. Round 14: with a trusted
                # Git 2.35, which resolves the boolean as a program, the boolean is incomplete too.
                if form == "boolean" and booleans_name_programs():
                    self.assertFalse(result["complete"])
                    self.assertEqual(result["incomplete_reasons"], [FSMONITOR_VERSION_REASON])
                elif form == "boolean":
                    self.assertTrue(result["complete"], result.get("incomplete_reasons"))
                else:
                    self.assertFalse(result["complete"])
                    self.assertIn(FSMONITOR_REASON, result["incomplete_reasons"])
                self.assertFalse([key for key in result["metadata"]["entries"] if key.startswith("dependency:core.fsmonitor")])
                self.assertFalse(marker.exists(), "the inspection path never runs the monitor")
                commands = [args for args, _ in launched if "--version" not in args]
                self.assertTrue(commands, "Git ran")
                for args, environment in launched:
                    self.assertIn(args[0], workspace_capture.TRUSTED_GIT_PATHS, "only the trusted Git is started")
                    self.assertFalse(any((form != "boolean" and value in arg) or str(program) in arg for arg in args), args)
                    self.assertFalse([name for name in environment if "FSMONITOR" in name or name == "GIT_CONFIG_PARAMETERS"])
                for args in commands:
                    pairs = list(zip(args, args[1:]))
                    self.assertIn(("-c", "core.fsmonitor=false"), pairs, "every Git command disables fsmonitor")
                    self.assertLess(pairs.index(("-c", "core.fsmonitor=false")), args.index("ls-files"))
                self.assertTrue(configs)
                self.assertFalse([data for data in configs if b"fsmonitor" in data.lower()],
                                 "the scratch repository's config never enables it")
                if form != "boolean":
                    # Control: ordinary git status runs this monitor.
                    subprocess.run(["git", "-C", str(repo), "status"], capture_output=True)
                    self.assertTrue(marker.exists(), "Git runs the configured monitor")

    # Defect 4: excluded roots ----------------------------------------------------------

    def test_excluded_root_failure_closes_every_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            for name in ("vendor_a", "vendor_b"):
                (repo / name).mkdir()
                (repo / name / "file").write_text("x\n", encoding="utf-8")
            parent, patches = private_scratch_parent(base)
            failing = FailingFrom("open", "_check_unwalked_attributes", PermissionError(errno.EACCES, "planted"), nth=2)
            before = open_descriptors()
            with patches[0], patches[1], patches[2], mock.patch.object(os, "open", failing):
                result = workspace_capture.capture(repo, max_files=1000, max_bytes=10_000_000, max_seconds=60,
                                                   max_entries=100_000, excluded_parts=frozenset({"vendor_a", "vendor_b"}))
            self.assertEqual(failing.calls, 2, "the second root failed after the first was opened")
            self.assertFalse(result["complete"])
            self.assertIn("unreadable directory", result["error"])
            self.assertTrue(all(descriptor_closed(fd) for fd in failing.results if isinstance(fd, int)))
            self.assertEqual(open_descriptors(), before, "every descriptor is released")
            self.assertEqual(list(parent.iterdir()), [])

    # Defect 5: scratch construction leftovers ---------------------------------------------

    def test_scratch_left_by_failed_construction_is_reported(self) -> None:
        real_rmdir = os.rmdir

        def failing_rmdir(path: object, *args: object, **kwargs: object) -> None:
            if os.fsdecode(path).startswith("cwo-inspect-"):  # type: ignore[arg-type]
                raise OSError(errno.EBUSY, "planted")
            real_rmdir(path, *args, **kwargs)  # type: ignore[arg-type]

        for seam in ("open", "fstat"):
            with self.subTest(failing=seam), tempfile.TemporaryDirectory() as tmpdir:
                base = Path(tmpdir)
                repo = make_repo(base)
                parent, patches = private_scratch_parent(base)
                failing = FailingFrom(seam, "_create_private_directory", OSError(errno.EIO, "planted"))
                before = open_descriptors()
                with patches[0], patches[1], patches[2], mock.patch.object(os, seam, failing), \
                        mock.patch.object(os, "rmdir", failing_rmdir):
                    result = workspace_capture.capture(repo, max_files=1000, max_bytes=10_000_000, max_seconds=60,
                                                       max_entries=100_000)
                self.assertEqual(failing.calls, 1)
                left = list(parent.iterdir())
                self.assertEqual(len(left), 1, "the directory that could not be removed is still there")
                self.assertFalse(result["complete"])
                self.assertEqual(result["error_kind"], "scratch-unavailable")
                self.assertEqual(os.path.realpath(result.get("scratch_abandoned") or ""), os.path.realpath(left[0]))
                reasons = " ".join(result["incomplete_reasons"])
                self.assertIn("could not be removed", reasons)
                self.assertIn(os.path.realpath(left[0]), reasons)
                self.assertEqual(open_descriptors(), before)

    def test_scratch_relocated_while_construction_fails_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            inside = repo / "inside"
            inside.mkdir()
            parent, patches = private_scratch_parent(base)
            moved = inside / "scratch-parent"
            failing = FailingFrom("fstat", "_create_private_directory", OSError(errno.EIO, "planted"),
                                  before=lambda: self.REAL_RENAME(parent, moved))
            before = open_descriptors()
            with patches[0], patches[1], patches[2], WriteRecorder() as recorder, mock.patch.object(os, "fstat", failing):
                result = workspace_capture.capture(repo, max_files=1000, max_bytes=10_000_000, max_seconds=60,
                                                   max_entries=100_000)
            self.assertEqual(failing.calls, 1)
            left = list(moved.iterdir())
            self.assertEqual(len(left), 1, "the new directory is abandoned where it now lies, not removed")
            self.assertEqual(recorder.inside(repo), [], "nothing is removed inside the workspace")
            self.assertFalse(result["complete"])
            self.assertEqual(result["error_kind"], "scratch-relocated")
            self.assertEqual(os.path.realpath(result.get("scratch_abandoned") or ""), os.path.realpath(left[0]))
            reasons = " ".join(result["incomplete_reasons"])
            self.assertIn("abandoned", reasons)
            self.assertIn(os.path.realpath(left[0]), reasons)
            self.assertEqual(open_descriptors(), before)


def deep_directories(base: Path, levels: int, files: int, *, name_length: int = 255, per_level: str | None = None) -> None:
    """``levels`` nested directories under ``base``, each named by ``name_length`` characters, over ``files`` empty
    files; ``per_level`` names a small file written in every directory. Built through descriptors, so the
    path length is never limited by PATH_MAX."""
    fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for level in range(levels):
            if per_level is not None:
                handle = os.open(per_level, os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC, 0o644, dir_fd=fd)
                os.write(handle, b"#\n")
                os.close(handle)
            name = f"{level:03d}".ljust(name_length, "d")
            os.mkdir(name, dir_fd=fd)
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        for number in range(files):
            os.close(os.open(f"f{number:04d}", os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC, 0o644, dir_fd=fd))
    finally:
        os.close(fd)


def stored_width(text: str) -> int:
    widest = max((ord(character) for character in text), default=0)
    return 1 if widest < 0x100 else 2 if widest < 0x10000 else 4


class RoundThirteenTests(unittest.TestCase):
    """Untracked path budgets, monitor configuration and symlink semantics."""

    # Major 1: filesystem path expansion is charged -------------------------------------

    @staticmethod
    def walker(root: Path, cap: int) -> workspace_capture.WorktreeCapture:
        """Production ``_walk`` state over ``root``, with the metadata byte budget capped at ``cap``."""
        probe = workspace_capture.WorktreeCapture(
            root, scope=workspace_capture.CaptureScope(),
            budget=workspace_capture.Budget.start(max_files=100_000, max_bytes=1 << 30, max_seconds=300, max_entries=1_000_000))
        probe.meta_budget.max_bytes = cap
        probe.inventory, probe.blobs, probe.unwalked = {}, {}, []
        probe.ignore_texts, probe.attribute_texts = {}, {}
        probe.index_paths, probe.gitlinks = set(), set()
        probe.raw_blobs, probe.link_targets, probe.object_format = {}, {}, "sha1"
        return probe

    def test_untracked_paths_are_charged_before_they_are_built(self) -> None:
        import tracemalloc

        # The reviewer's tree on a real filesystem: 300 levels of 255-character directories over
        # 1,000 empty files, about 1,300 entries expanding to about 90 MB of paths.
        with self.subTest(part="production _walk, the reviewer's tree"), tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            deep_directories(root, 300, 1_000)
            probe = self.walker(root, 4 << 20)
            before = open_descriptors()
            probe.root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            tracemalloc.start()
            try:
                with self.assertRaisesRegex(workspace_capture.BudgetExhausted, "byte cap"):
                    probe._walk()
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
                os.close(probe.root_fd)
            self.assertGreater(probe.meta_budget.bytes, 4 << 20, "the expansion is charged (zero bytes before)")
            self.assertLess(peak, 8 << 20, "allocation stays within the charged budget (about 90 MB before)")
            self.assertEqual(open_descriptors(), before, "every directory descriptor is closed")

        # Exact accounting: each path and each directory prefix is charged its length times the
        # storage width of its widest character, before it is built.
        with self.subTest(part="exact accounting"), tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            for directory in ("plain", "€uro/sub", "\U0001F600", "café"):
                (root / directory).mkdir(parents=True)
            for file in ("top", "plain/a", "€uro/x", "€uro/sub/y", "\U0001F600/z", "café/b"):
                (root / file).write_bytes(b"")
            probe = self.walker(root, 1 << 20)
            probe.root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                probe._walk()
            finally:
                os.close(probe.root_fd)
            expected = 0
            for path, value in probe.inventory.items():
                width = stored_width(path)
                expected += len(path) * width
                if value.startswith("directory:"):
                    expected += (len(path) + 1) * width  # the prefix its entries are built from
            self.assertEqual(len(probe.inventory), 11)
            self.assertEqual(probe.meta_budget.bytes, expected)

        # Through capture: an untracked tree, independent of HEAD, is a budget incomplete capture,
        # with allocation bounded by the (here 4 MiB) metadata byte budget.
        with self.subTest(part="through capture"), tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            deep_directories(repo / "src", 300, 1_000)
            tracemalloc.start()
            try:
                with mock.patch.object(workspace_capture, "METADATA_BYTES", 4 << 20):
                    result = workspace_capture.capture(repo, max_files=10_000, max_bytes=500_000_000, max_seconds=300,
                                                       max_entries=1_000_000)
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
            self.assertFalse(result["complete"])
            self.assertEqual(result["error_kind"], "budget", result.get("error"))
            self.assertIn("byte cap", result["error"])
            self.assertLess(peak, 16 << 20)
            # And with the default budget.
            evidence = capture_workspace_baseline(repo, allowed_paths=["src"], max_seconds=300)
            self.assertTrue(evidence["incomplete"])
            self.assertIn("byte cap", " ".join(evidence["incomplete_reasons"]))

    def test_metadata_and_excluded_paths_are_charged_before_they_are_built(self) -> None:
        import tracemalloc

        def capped(repo: Path, **scope: object) -> tuple[dict, int]:
            tracemalloc.start()
            try:
                with mock.patch.object(workspace_capture, "METADATA_BYTES", 4 << 20):
                    result = workspace_capture.capture(repo, max_files=10_000, max_bytes=500_000_000, max_seconds=300,
                                                       max_entries=1_000_000, **scope)  # type: ignore[arg-type]
                return result, tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()

        # Metadata keys: a deep hooks tree, keyed by its whole path below the hooks directory.
        with self.subTest(part="metadata keys"), tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            deep_directories(repo / ".git" / "hooks", 300, 1_000)
            result, peak = capped(repo)
            self.assertFalse(result["complete"])
            self.assertEqual(result["error_kind"], "budget", result.get("error"))
            self.assertIn("byte cap", result["error"])
            self.assertLess(peak, 16 << 20, "about 90 MB of keys before")
        # Repository tree labels checked before Git runs.
        with self.subTest(part="preflight labels"), tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            deep_directories(repo / ".git" / "refs" / "heads", 300, 0)
            result, _ = capped(repo)
            self.assertFalse(result["complete"])
            self.assertEqual(result["error_kind"], "budget", result.get("error"))
            self.assertIn("byte cap", result["error"])
        # Excluded directories: each label below one, and each .gitattributes kept, is charged.
        with self.subTest(part="excluded directories"), tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            (repo / "vendor").mkdir()
            deep_directories(repo / "vendor", 300, 0, per_level=".gitattributes")
            result, peak = capped(repo, excluded_parts=frozenset({"vendor"}))
            self.assertFalse(result["complete"])
            self.assertEqual(result["error_kind"], "budget", result.get("error"))
            self.assertIn("byte cap", result["error"])
            self.assertLess(peak, 16 << 20)

    # Majors 2 and 3: fsmonitor values are booleans only ---------------------------------------

    def test_fsmonitor_programs_make_the_capture_incomplete(self) -> None:
        def configure(base: Path, repo: Path, form: str) -> tuple[str, Path]:
            """The value for ``form`` and the file a change to which must not go unreported."""
            outside = base / "outside"
            (outside / "sub").mkdir(parents=True)
            if form == "link/../watch":
                # Lexically repo/watch; the filesystem resolves it to outside/watch.
                (repo / "link").symlink_to(outside / "sub", target_is_directory=True)
                (repo / "watch").write_text("#!/bin/sh\n", encoding="utf-8")
                program = outside / "watch"
                program.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
                program.chmod(0o755)
                return "link/../watch", program
            if form == "interpreter with worktree 2":
                # Python would run worktree file 2, a symlink to an external script.
                script = outside / "monitor.py"
                script.write_text("print()\n", encoding="utf-8")
                (repo / "2").symlink_to(script)
                return "/usr/bin/python3", script
            program = repo / "src" / "watch" if form == "relative" else base / "hook"
            program.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            program.chmod(0o755)
            return ("src/watch" if form == "relative" else str(program)), program

        for form in ("link/../watch", "interpreter with worktree 2", "relative", "absolute"):
            with self.subTest(form=form), tempfile.TemporaryDirectory() as tmpdir:
                base = Path(tmpdir)
                repo = make_repo(base)
                value, dependency = configure(base, repo, form)
                git(repo, "config", "core.fsmonitor", value)
                before = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertTrue(before["incomplete"], "the program's dependencies cannot be established")
                self.assertIn(FSMONITOR_REASON, before["incomplete_reasons"])
                self.assertFalse([key for key in before["git_metadata"]["entries"] if key.startswith("dependency:core.fsmonitor")],
                                 "no program dependency is constructed")
                # The reviewer's probe: a change to what the program would read is never taken as complete and clean.
                dependency.write_text(dependency.read_text(encoding="utf-8") + "# planted\n", encoding="utf-8")
                after = capture_workspace_baseline(repo, allowed_paths=["src"])
                report = compare_workspace_baseline(before, after, allowed_paths=["src"])
                self.assertTrue(report["unexpected_mutation_detected"], report)

    def test_boolean_fsmonitor_values_are_complete_captures(self) -> None:
        # Round 14: version-aware. From Git 2.36 every boolean is a complete capture; Git 2.35 resolves any
        # non-empty value as a program, so only the empty value and the valueless key (which 2.35 refuses
        # as a config error, running nothing) stay complete. Each value is captured as the trusted Git's
        # own release, then as 2.35.8 and as 2.36.6.
        for value in ("true", "false", "yes", "no", "on", "off", "1", "0", "TRUE", "Off", "2", "", None):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                if value is None:
                    # A key with no value, which Git 2.36 and later read as true.
                    with (repo / ".git" / "config").open("a", encoding="utf-8") as handle:
                        handle.write("[core]\n\tfsmonitor\n")
                else:
                    git(repo, "config", "core.fsmonitor", value)
                for version in (trusted_git_version(), (2, 35, 8), (2, 36, 6)):
                    with reporting_git_version(version):
                        result = workspace_capture.capture(repo, max_files=1000, max_bytes=10_000_000, max_seconds=60,
                                                           max_entries=100_000)
                    if value and booleans_name_programs(version):
                        self.assertFalse(result["complete"], version)
                        self.assertEqual(result["incomplete_reasons"], [FSMONITOR_VERSION_REASON])
                    else:
                        self.assertTrue(result["complete"], (version, result.get("incomplete_reasons")))
                    self.assertFalse([key for key in result["metadata"]["entries"] if key.startswith("dependency:core.fsmonitor")])

    # The `..` audit ------------------------------------------------------------------------------

    def test_hooks_paths_are_never_normalized_across_a_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            outside = base / "outside"
            (outside / "sub").mkdir(parents=True)
            (outside / "hooks").mkdir()
            (outside / "hooks" / "pre-commit").write_text("#!/bin/sh\n", encoding="utf-8")
            (repo / "hooks").mkdir()
            (repo / "hooks" / "pre-commit").write_text("#!/bin/sh\n", encoding="utf-8")
            (repo / "link").symlink_to(outside / "sub", target_is_directory=True)
            # Lexically repo/hooks; the filesystem (and Git) reach outside/hooks.
            git(repo, "config", "core.hooksPath", "link/../hooks")
            before = capture_workspace_baseline(repo, allowed_paths=["src"])
            self.assertTrue(before["incomplete"])
            self.assertIn("core.hookspath holds a '..' component", " ".join(before["incomplete_reasons"]))
            self.assertFalse([key for key in before["git_metadata"]["entries"] if key.startswith("dependency:core.hookspath")],
                             "the lexically normalized directory is not recorded in its place")
            (outside / "hooks" / "pre-commit").write_text("#!/bin/sh\necho planted\n", encoding="utf-8")
            after = capture_workspace_baseline(repo, allowed_paths=["src"])
            self.assertTrue(compare_workspace_baseline(before, after, allowed_paths=["src"])["unexpected_mutation_detected"])
        for value in ("../hooks", "src/..", "~/../hooks", "/tmp/../hooks", "src/./../hooks"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                git(repo, "config", "core.hooksPath", value)
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertTrue(evidence["incomplete"])
                self.assertIn("core.hookspath holds a '..' component", " ".join(evidence["incomplete_reasons"]))
        for value in ("~nobody/hooks", "~nobody", "%(prefix)/hooks"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                git(repo, "config", "core.hooksPath", value)
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertTrue(evidence["incomplete"])
                self.assertIn("core.hookspath uses a home or prefix expansion", " ".join(evidence["incomplete_reasons"]))
        # Control: "." components, repeated slashes, "~/" and names that merely begin with ".." still name
        # the directory, which is snapshotted.
        for value in ("./src//hooks/", "~/hooks", "src/..hooks"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmpdir:
                base = Path(tmpdir)
                repo = make_repo(base)
                home = base / "home"
                for hooks in (repo / "src" / "hooks", home / "hooks", repo / "src" / "..hooks"):
                    hooks.mkdir(parents=True)
                    (hooks / "pre-commit").write_text("#!/bin/sh\n", encoding="utf-8")
                git(repo, "config", "core.hooksPath", value)
                with mock.patch.dict(os.environ, {"HOME": str(home)}):
                    evidence = capture_workspace_baseline(repo, allowed_paths=["docs"])
                self.assertFalse(evidence["incomplete"], evidence.get("incomplete_reasons"))
                entries = evidence["git_metadata"]["entries"]
                self.assertEqual(entries[f"dependency:core.hookspath:{value}"]["kind"], "directory")
                self.assertEqual(entries[f"dependency:core.hookspath:{value}/pre-commit"]["kind"], "file")

    def test_scratch_candidates_are_resolved_by_the_filesystem(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(os.path.realpath(tmpdir))
            repo = make_repo(base)
            (base / "deep" / "sub").mkdir(parents=True)
            (base / "link").symlink_to(base / "deep" / "sub", target_is_directory=True)
            # Lexically base; the filesystem resolves it to base/deep.
            candidate = f"{base}/link/.."
            environment = {name: candidate for name in ("TMPDIR", "TEMP", "TMP")}
            with mock.patch.object(tempfile, "tempdir", None), mock.patch.dict(os.environ, environment), \
                    mock.patch.object(workspace_capture, "SCRATCH_PARENTS", ()):
                self.assertEqual(workspace_capture._scratch_candidates(), [candidate])
                parent_fd, fd, name, path, *_ = workspace_capture._scratch_directory((str(repo), str(repo / ".git")))
                try:
                    self.assertEqual(os.path.dirname(path), str(base / "deep"))
                    self.assertTrue((base / "deep" / name).is_dir())
                finally:
                    os.close(fd)
                    os.rmdir(name, dir_fd=parent_fd)
                    os.close(parent_fd)
                state = capture_tracked_workspace_state(repo, include_untracked=True)
            self.assertFalse(state["incomplete"], state.get("incomplete_reasons"))
            self.assertEqual(sorted(path.name for path in (base / "deep").iterdir()), ["sub"], "the scratch is removed")


def deep_absent_index(repo: Path, count: int, levels: int) -> list[str]:
    """``count`` distinct skip-worktree index entries, each ``levels`` components deep, sharing no directory
    and absent from the worktree (the reviewer's shape: about 610 characters each)."""
    blob = subprocess.run(["git", "-C", str(repo), "hash-object", "-w", "--stdin"], input=b"x\n",
                          check=True, capture_output=True).stdout.decode().strip()
    paths = [f"{number:04d}/" + "d/" * (levels - 2) + "f" for number in range(count)]
    records = "".join(f"100644 {blob}\t{path}\0" for path in paths).encode()
    subprocess.run(["git", "-C", str(repo), "update-index", "-z", "--index-info"], input=records, check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "update-index", "--skip-worktree", "-z", "--stdin"],
                   input="".join(path + "\0" for path in paths).encode(), check=True, capture_output=True)
    return paths


def raw_capture(index_paths: list[str], inventory: dict[str, str]) -> dict[str, object]:
    """A successful raw capture holding ``index_paths`` (skip-worktree) and ``inventory``, for ``_capture_fields``."""
    return {
        "git_executable": {"path": "/usr/bin/git", "version": "2.56.0"}, "capture_identity": {}, "object_format": "sha1",
        "head": "unborn", "head_manifest_sha256": "0" * 64,
        "index_entries": [["100644", "1" * 40, 0, path, "S"] for path in index_paths],
        "raw_inventory": inventory, "ignored_directories": [], "sparse_directories": [], "normalization_sources": [],
        "git_cleanliness": "raw-equals-git", "metadata": {"entries": {}}, "incomplete_reasons": [],
    }


class RoundFourteenTests(unittest.TestCase):
    """Absent index paths, ignored directories and filesystem monitor parsing."""

    # Major 1: ancestors of index paths are never built ---------------------------------------

    def test_deep_absent_index_paths_build_no_ancestors(self) -> None:
        import tracemalloc

        # The reviewer's probe on production _capture_fields: 1,000 distinct paths, each 300 levels deep
        # (610,000 characters), peaked at about 114 MB building every ancestor, whatever the scope.
        paths = [f"{number:04d}/" + "d/" * 298 + "f" for number in range(1_000)]
        self.assertEqual(sum(map(len, paths)), 602_000)
        inventory = {".gitignore": "file:644:0:-", "0000": "directory:755:0:-", "notes.txt": "file:644:0:-"}
        for include_untracked in (True, False):
            with self.subTest(include_untracked=include_untracked):
                raw = raw_capture(paths, dict(inventory))
                tracemalloc.start()
                try:
                    fields = workspace._capture_fields(raw, include_untracked, ["src"])
                    peak = tracemalloc.get_traced_memory()[1]
                finally:
                    tracemalloc.stop()
                self.assertLess(peak, 4 << 20, "no ancestor is built (about 114 MB before)")
                expected = inventory if include_untracked else {"0000": "directory:755:0:-"}
                self.assertEqual(fields["raw_inventory"], expected)

        # Exact selection without untracked status: tracked entries, entries on or under a declared path,
        # and every directory above either, decided by components ("a-b" and "a.b" sort between "a" and
        # "a/", and "ab" after it).
        tracked = ["a/x", "a-b/c", "deep/er/file", "top"]
        inventory = {name: "directory:755:0:-" for name in ("a", "a-b", "a.b", "ab", "deep", "deep/er", "deep/e", "docs", "docs/sub", "other")}
        inventory.update({path: "file:644:0:-" for path in ("a/x", "a-b/c", "a.b/y", "ab/z", "top", "topper", "docs/sub/new.txt", "docs/sub/new.txt.bak", "other/u")})
        inventory["deep/er/file"] = "symlink:777:4:-"
        fields = workspace._capture_fields(raw_capture(tracked, inventory), False, ["./docs//sub/new.txt", "../escape", "/abs"])
        self.assertEqual(sorted(fields["raw_inventory"]), [
            "a", "a-b", "a-b/c", "a/x", "deep", "deep/er", "deep/er/file", "docs", "docs/sub", "docs/sub/new.txt", "top"])
        self.assertEqual(list(fields["raw_inventory"]), [path for path in inventory if path in fields["raw_inventory"]],
                         "inventory order is kept")

    def test_deep_absent_index_paths_are_bounded_through_capture(self) -> None:
        import tracemalloc

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = base / "repo"
            repo.mkdir()
            git(repo, "init", "-q")  # HEAD stays unborn
            configure_git_fixture(repo)
            (repo / "src").mkdir()
            (repo / "src" / "new.txt").write_text("new\n", encoding="utf-8")
            paths = deep_absent_index(repo, 1_000, 300)
            calls = {
                "state, tracked": lambda: capture_tracked_workspace_state(repo, include_untracked=False),
                "state, tracked and untracked": lambda: capture_tracked_workspace_state(repo, include_untracked=True),
                "baseline, tracked": lambda: capture_workspace_baseline(repo, allowed_paths=["src"], include_untracked=False, max_seconds=120),
                "baseline, tracked and untracked": lambda: capture_workspace_baseline(repo, allowed_paths=["src"], include_untracked=True, max_seconds=120),
            }
            for label, call in calls.items():
                with self.subTest(scope=label):
                    tracemalloc.start()
                    try:
                        evidence = call()
                        peak = tracemalloc.get_traced_memory()[1]
                    finally:
                        tracemalloc.stop()
                    # The ordinary path: a complete capture, each absent skip-worktree entry an addition.
                    self.assertFalse(evidence["incomplete"], evidence.get("incomplete_reasons"))
                    self.assertEqual(len(evidence["index_entries"]), 1_000)
                    self.assertEqual(sorted(line for line in evidence["tracked_status"] if line.startswith("A ")),
                                     sorted(f"A  {path}" for path in paths))
                    self.assertEqual("?? src/new.txt" in evidence["tracked_status"], "and untracked" in label)
                    self.assertEqual("src/new.txt" in evidence["raw_inventory"], label != "state, tracked")
                    self.assertLess(peak, 12 << 20, "bounded by the captured paths (above 114 MB before)")

            # Budget refusal: the index paths that reach evidence are charged to the capture's Git output budget
            # as Git streams them; past it the capture is a budget refusal, and no evidence is built from them.
            for include_untracked in (False, True):
                with self.subTest(refusal=include_untracked), \
                        mock.patch.object(workspace_capture, "GIT_OUTPUT_CAP", 256 << 10):
                    tracemalloc.start()
                    try:
                        state = capture_tracked_workspace_state(repo, include_untracked=include_untracked)
                        baseline = capture_workspace_baseline(repo, allowed_paths=["src"], include_untracked=include_untracked)
                        peak = tracemalloc.get_traced_memory()[1]
                    finally:
                        tracemalloc.stop()
                    for evidence in (state, baseline):
                        self.assertEqual(evidence["error_kind"], "budget", evidence.get("error"))
                        self.assertIn("byte cap", evidence["error"])
                        self.assertTrue(evidence["incomplete"])
                        self.assertEqual(evidence["raw_inventory"], {})
                    self.assertLess(peak, 8 << 20)

    def test_ignored_directories_are_matched_without_scanning_each_one(self) -> None:
        # Untracked status skips names under an ignored directory: one ordered lookup per name, not a scan
        # of every ignored directory (a quadratic loop between deadline checks before).
        probe = workspace_capture.WorktreeCapture(
            Path("/workspace"), scope=workspace_capture.CaptureScope(),
            budget=workspace_capture.Budget.start(max_files=0, max_bytes=0, max_seconds=60, max_entries=0))
        probe.blobs, probe.ignored_files = {}, set()
        probe.ignored_dirs = ("a/", "a/b/", "build/", "c-d/", "c/")
        probe.inventory = {path: "file:644:0:-" for path in (
            "a/x", "a/b/y", "ab", "b", "build/out", "buildx", "c-d/e", "c.d", "c/e", "d/c/e", "z")}
        probe.inventory["c-d"] = "directory:755:0:-"
        self.assertEqual(probe._status([], {}), ["?? ab", "?? b", "?? buildx", "?? c.d", "?? d/c/e", "?? z"])
        calls: list[str] = []

        class Counting(str):
            def startswith(self, *args: object) -> bool:  # type: ignore[override]
                calls.append(str(self))
                return str.startswith(self, *args)  # type: ignore[arg-type]

        probe.ignored_dirs = tuple(f"i{number:05d}/" for number in range(2_000))
        probe.inventory = {Counting(f"u{number:05d}"): "file:644:0:-" for number in range(2_000)}
        self.assertEqual(len(probe._status([], {})), 2_000)
        self.assertLess(len(calls), 3 * 2_000, "at most a few comparisons per name (four million before)")

    def test_comparison_reads_preexisting_dirt_once(self) -> None:
        # The pre-existing dirty paths were turned into a set once per compared path (quadratic).
        reads = [0]

        class Counted(list):
            def __iter__(self):  # type: ignore[no-untyped-def]
                reads[0] += 1
                return super().__iter__()

        paths = [f"p{number:05d}" for number in range(2_000)]
        before = {"tracked_status": [f" M {path}" for path in paths], "preexisting_dirty_paths": Counted(paths),
                  "content_fingerprints": {}, "evidence_version": workspace.EVIDENCE_VERSION, "allowed_paths": []}
        after = {**before, "tracked_status": [f"MM {path}" for path in paths], "preexisting_dirty_paths": []}
        report = compare_workspace_baseline(before, after, allowed_paths=[])
        self.assertEqual(len(report["mutations"]), 2_000)
        self.assertEqual(reads[0], 1)

    def test_gitignore_entries_that_are_not_files_are_still_refused(self) -> None:
        # The check now compares names in place; what it refuses is unchanged.
        for name in (".gitignore", "src/.gitignore", "src/deeper/.gitignore"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmpdir:
                base = Path(tmpdir)
                repo = make_repo(base)
                (base / "patterns").write_text("*.log\n", encoding="utf-8")
                (repo / name).parent.mkdir(parents=True, exist_ok=True)
                (repo / name).symlink_to(base / "patterns")
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertEqual(evidence["error_kind"], "git-failed", evidence.get("error"))
                self.assertIn(f"a .gitignore entry is not a regular file: {name}", evidence["error"])
        # Control: names that merely end in ".gitignore" are ordinary entries.
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            (base / "patterns").write_text("*.log\n", encoding="utf-8")
            for name in ("x.gitignore", "src/a.gitignore"):
                (repo / name).symlink_to(base / "patterns")
            evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
            self.assertFalse(evidence["incomplete"], evidence.get("incomplete_reasons"))

    # Major 2: Git 2.35 resolves boolean-looking fsmonitor values as programs ----------------

    def test_fsmonitor_values_are_read_as_the_trusted_git_reads_them(self) -> None:
        def probe(version: tuple[int, ...], value: str | None) -> workspace_capture.WorktreeCapture:
            capture = workspace_capture.WorktreeCapture(
                Path("/workspace"), scope=workspace_capture.CaptureScope(),
                budget=workspace_capture.Budget.start(max_files=0, max_bytes=0, max_seconds=60, max_entries=0))
            capture.git = workspace_capture.GitExecutable("/usr/bin/git", (0, 0, 0, 0), version)
            capture.state = workspace_capture._State()
            capture.dependencies, capture.config_files, capture.conversion_sources = {}, set(), set()
            capture.config_entries = {"/workspace/.git/config": [("core.fsmonitor", value)]}
            capture._config()
            return capture

        booleans = ("true", "false", "yes", "no", "on", "off", "1", "0", "2", "TRUE", "Off", "-1")
        for version in ((2, 35, 8), (2, 35, 0), (2, 36, 0), (2, 36, 6), (2, 56, 0)):
            for value in (*booleans, "", None, "src/watch", "true --"):
                with self.subTest(version=version, value=value):
                    capture = probe(version, value)
                    if value in ("src/watch", "true --"):
                        expected = [FSMONITOR_REASON]
                    elif value and version[:2] == (2, 35):
                        expected = [FSMONITOR_VERSION_REASON]
                    else:
                        expected = []
                    self.assertEqual(capture.state.reasons, expected)
                    self.assertEqual(capture.dependencies, {})

    def test_boolean_monitor_found_on_path_through_the_worktree_is_incomplete_on_git_2_35(self) -> None:
        # The reviewer's case: PATH holds repo/bin, where bin/true is a symlink to an external monitor.
        # Git 2.35 runs it for core.fsmonitor=true; changing its referent changes neither the recorded
        # symlink nor any fsmonitor dependency, so the capture must not be complete.
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            marker = base / "monitor-ran"
            monitor = base / "outside" / "monitor"
            monitor.parent.mkdir()
            monitor.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n", encoding="utf-8")
            monitor.chmod(0o755)
            (repo / "bin").mkdir()
            (repo / "bin" / "true").symlink_to(monitor)
            git(repo, "config", "core.fsmonitor", "true")
            (repo / "src" / "app.py").write_text("print('b')\n", encoding="utf-8")
            path = f"{repo / 'bin'}:{os.environ.get('PATH', '/usr/bin:/bin')}"
            with mock.patch.dict(os.environ, {"PATH": path}):
                with reporting_git_version((2, 35, 8)):
                    before = capture_workspace_baseline(repo, allowed_paths=["src"])
                    self.assertTrue(before["incomplete"])
                    self.assertEqual(before["incomplete_reasons"], [FSMONITOR_VERSION_REASON])
                    self.assertFalse([key for key in before["git_metadata"]["entries"] if key.startswith("dependency:core.fsmonitor")])
                    monitor.write_text(f"#!/bin/sh\ntouch '{marker}'\n# planted\nexit 1\n", encoding="utf-8")
                    after = capture_workspace_baseline(repo, allowed_paths=["src"])
                    report = compare_workspace_baseline(before, after, allowed_paths=["src"])
                # The recorded symlink and metadata are unchanged; only the refusal keeps the report unexpected.
                self.assertEqual(before["raw_inventory"]["bin/true"], after["raw_inventory"]["bin/true"])
                self.assertEqual(before["git_metadata"]["entries"], after["git_metadata"]["entries"])
                self.assertTrue(report["incomplete"])
                self.assertTrue(report["unexpected_mutation_detected"])
                self.assertFalse(marker.exists(), "the inspection path never runs the monitor")
                # From 2.36 the value is a boolean: nothing is run, and the capture is complete.
                with reporting_git_version((2, 36, 6)):
                    later = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertFalse(later["incomplete"], later.get("incomplete_reasons"))
                self.assertIn(" M src/app.py", later["tracked_status"])
                self.assertFalse(marker.exists(), "the inspection path never runs the monitor")
                # Under the trusted Git's own version, whichever this is.
                own = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertEqual(own["incomplete"], booleans_name_programs())
                self.assertFalse(marker.exists(), "the inspection path never runs the monitor")
                # Control: ordinary git status with this PATH runs the external monitor on 2.35 only.
                subprocess.run(["git", "-C", str(repo), "status"], capture_output=True, env=dict(os.environ))
                self.assertEqual(marker.exists(), booleans_name_programs(),
                                 "2.35 runs bin/true from PATH; 2.36 and later read the value as a boolean")


def oracle_manifest(repo: Path) -> tuple[str, str]:
    """HEAD's tree and manifest digest as Git itself reports them (tests may run Git directly)."""
    tree = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"], check=True, capture_output=True, text=True).stdout.strip()
    raw = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "-z", "--full-tree", tree], check=True, capture_output=True).stdout
    manifest = {}
    for record in raw.split(b"\0"):
        if record:
            meta, _, path = record.partition(b"\t")
            mode, _, oid = meta.decode().split(" ")
            manifest[path.decode("utf-8", errors="surrogateescape")] = (mode, oid)
    import hashlib

    return tree, hashlib.sha256(repr(sorted(manifest.items())).encode()).hexdigest()


def packed_tree_delta_types(repo: Path) -> set[int]:
    """Pack entry types (6 offset delta, 7 reference delta) of the deltified trees in ``repo``'s packs."""
    types = set()
    for idx in (repo / ".git" / "objects" / "pack").glob("*.idx"):
        listing = subprocess.run(["git", "verify-pack", "-v", str(idx)], check=True, capture_output=True, text=True).stdout
        data = idx.with_suffix(".pack").read_bytes()
        for line in listing.splitlines():
            fields = line.split()
            if len(fields) >= 7 and fields[1] == "tree":
                types.add((data[int(fields[4])] >> 4) & 7)
    return types


class StableViewTests(unittest.TestCase):
    """Git reads only a private snapshot; HEAD, refs and config are read without Git."""

    def test_git_only_ever_runs_inside_the_private_snapshot(self) -> None:
        calls: list[tuple[str, str | None, str | None, tuple[str, ...]]] = []
        real = workspace_capture.run_git

        def recording(git: object, root: object, args: list[str], **kwargs: object) -> object:
            calls.append((str(root), kwargs.get("git_dir"), kwargs.get("work_tree"), tuple(args)))  # type: ignore[arg-type]
            return real(git, root, args, **kwargs)  # type: ignore[arg-type]

        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            (repo / ".gitignore").write_text("*.log\n", encoding="utf-8")
            (repo / "debug.log").write_text("x\n", encoding="utf-8")
            (repo / "notes.md").write_text("x\n", encoding="utf-8")
            with mock.patch.object(workspace_capture, "run_git", side_effect=recording):
                state = capture_tracked_workspace_state(repo, include_untracked=True)
            live = {os.path.realpath(repo), os.path.realpath(repo / ".git")}
        self.assertFalse(state["incomplete"], state.get("incomplete_reasons"))
        self.assertIn("?? notes.md", state["tracked_status"])
        self.assertNotIn("?? debug.log", state["tracked_status"])
        self.assertEqual([call[3][0] for call in calls], ["ls-files", "ls-files"])
        roots = set()
        for root, git_dir, work_tree, _ in calls:
            self.assertIsNotNone(git_dir)
            self.assertEqual(root, work_tree)
            for path in (root, git_dir):
                real_path = os.path.realpath(str(path))
                self.assertFalse(any(real_path == item or real_path.startswith(item + os.sep) for item in live), real_path)
            roots.add(os.path.dirname(os.path.realpath(str(git_dir))))
        self.assertEqual(len(roots), 1)
        self.assertFalse(os.path.exists(roots.pop()), "the snapshot is removed after the capture")

    def test_repository_files_replaced_after_preflight_never_reach_git(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            real_preflight = workspace_capture.WorktreeCapture._preflight
            fifo = repo / ".git" / "info" / "exclude"
            woke_thread: list[tuple[object, object]] = []

            def preflight_then_replace(capture: object) -> None:
                real_preflight(capture)  # type: ignore[arg-type]
                if capture.root == repo and not woke_thread:  # type: ignore[attr-defined]
                    fifo.unlink(missing_ok=True)
                    os.mkfifo(fifo)
                    woke_thread.append(fifo_writer(fifo))

            with mock.patch.object(workspace_capture.WorktreeCapture, "_preflight", preflight_then_replace):
                try:
                    evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                    woke, _ = woke_thread[0]
                    self.assertFalse(woke.wait(0.5), "neither Git nor the capture opens the substituted FIFO")
                finally:
                    release(fifo, woke_thread[0][1])
        self.assertTrue(evidence["incomplete"])
        self.assertIn("not a regular file", " ".join(evidence["incomplete_reasons"]))

    def test_head_tree_is_read_exactly_as_git_reads_it(self) -> None:
        def loose(repo: Path) -> None:
            pass

        def tree_deltas(offset_deltas: bool) -> object:
            def prepare(repo: Path) -> None:
                # Large trees that differ by one entry are stored as deltas.
                (repo / "many").mkdir()
                for number in range(300):
                    (repo / "many" / f"f{number}.txt").write_text(f"file {number}\n", encoding="utf-8")
                git(repo, "add", "-A")
                git(repo, "commit", "-qm", "many")
                for version in range(3):
                    (repo / "many" / "f7.txt").write_text(f"change {version}\n", encoding="utf-8")
                    git(repo, "commit", "-qam", f"v{version}")
                subprocess.run(["git", "-C", str(repo), "-c", f"repack.useDeltaBaseOffset={str(offset_deltas).lower()}", "gc", "-q",
                                "--aggressive", "--prune=now"], check=True, capture_output=True)
                git(repo, "pack-refs", "--all")
                self.assertIn(6 if offset_deltas else 7, packed_tree_delta_types(repo), "the pack holds tree deltas of this kind")
            return prepare

        def entry_kinds(repo: Path) -> None:
            (repo / "src" / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
            os.chmod(repo / "src" / "run.sh", 0o755)
            (repo / "link").symlink_to("src/app.py")
            head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
            git(repo, "update-index", "--add", "--cacheinfo", f"160000,{head},vendor/sub")
            git(repo, "add", "-A")
            git(repo, "commit", "-qm", "kinds")

        def detached(repo: Path) -> None:
            git(repo, "checkout", "-q", "--detach")

        for label, prepare in (("loose", loose), ("offset tree deltas", tree_deltas(True)), ("reference tree deltas", tree_deltas(False)),
                               ("modes, symlink, gitlink", entry_kinds), ("detached", detached)):
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                prepare(repo)
                evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
                self.assertFalse(evidence.get("error"), evidence.get("incomplete_reasons"))
                self.assertEqual((evidence["head"], evidence["head_manifest_sha256"]), oracle_manifest(repo))

    def test_sha256_repositories_are_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "repo"
            subprocess.run(["git", "init", "-q", "--object-format=sha256", str(repo)], check=True)
            configure_git_fixture(repo)
            git(repo, "config", "user.email", "t@example.invalid")
            git(repo, "config", "user.name", "t")
            (repo / "a.txt").write_text("a\n", encoding="utf-8")
            git(repo, "add", "-A")
            git(repo, "commit", "-qm", "init")
            git(repo, "gc", "-q")
            evidence = capture_workspace_baseline(repo, allowed_paths=["a.txt"])
            self.assertEqual(evidence["object_format"], "sha256")
            self.assertEqual((evidence["head"], evidence["head_manifest_sha256"]), oracle_manifest(repo))
            self.assertEqual(evidence["tracked_status"], [])

    def test_missing_objects_are_never_fetched(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            tree = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"], check=True, capture_output=True, text=True).stdout.strip()
            (repo / ".git" / "objects" / tree[:2] / tree[2:]).unlink()
            evidence = capture_workspace_baseline(repo, allowed_paths=["src"])
        self.assertTrue(evidence["incomplete"])
        self.assertIn("nothing is fetched", " ".join(evidence["incomplete_reasons"]))

    def test_ignored_names_are_classified_exactly_as_git_classifies_them(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = make_repo(Path(tmpdir))
            (repo / ".gitignore").write_text("*.log\nbuild/\n!keep.log\n/anchored.txt\ndocs/**/*.tmp\n", encoding="utf-8")
            (repo / "src" / ".gitignore").write_text("generated/\n*.out\n", encoding="utf-8")
            (repo / ".git" / "info" / "exclude").write_text("secret.txt\n", encoding="utf-8")
            for name in ("a.log", "keep.log", "build/x.o", "anchored.txt", "sub/anchored.txt", "docs/a/b/c.tmp", "docs/a/b/c.md",
                         "src/generated/g.py", "src/x.out", "src/y.py", "secret.txt", "notes.md", "dir with space/file name.txt"):
                path = repo / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("x\n", encoding="utf-8")
            (repo / "dangling").symlink_to("nowhere")
            state = capture_tracked_workspace_state(repo, include_untracked=True)
            raw = subprocess.run(["git", "-C", str(repo), "status", "--porcelain=v1", "-z", "--untracked-files=all"],
                                 check=True, capture_output=True).stdout
        expected = sorted(record.decode() for record in raw.split(b"\0") if record.startswith(b"?? "))
        self.assertFalse(state["incomplete"], state.get("incomplete_reasons"))
        self.assertEqual(sorted(line for line in state["tracked_status"] if line.startswith("?? ")), expected)

    def test_discovery_and_the_pool_common_directory_never_run_git(self) -> None:
        from cwo_core.native_pool_workspace import _git_common_dir

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = make_repo(base)
            linked = base / "linked"
            git(repo, "worktree", "add", "-q", str(linked))
            with mock.patch.object(workspace_capture, "run_git", side_effect=AssertionError("git must not run")):
                self.assertEqual(workspace_capture.worktree_top_level(repo / "src"), str(repo.resolve()))
                self.assertEqual(workspace_capture.worktree_top_level(linked), str(linked.resolve()))
                self.assertEqual(_git_common_dir(linked), (repo / ".git").resolve())
                self.assertIsNone(workspace_capture.worktree_top_level(base))

    def test_layouts_read_differently_are_refused(self) -> None:
        cases = {
            "core.worktree": [("core.worktree", "/elsewhere")],
            "unknown extension": [("core.repositoryformatversion", "1"), ("extensions.unknownthing", "true")],
            "reftable": [("core.repositoryformatversion", "1"), ("extensions.refstorage", "reftable")],
            "v1-only extension at version 0": [("extensions.objectformat", "sha256")],
        }
        for label, settings in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmpdir:
                repo = make_repo(Path(tmpdir))
                for key, value in settings:
                    git(repo, "config", key, value)
                with self.assertRaises(workspace_capture.WorkspaceDiscoveryError):
                    workspace_capture.worktree_top_level(repo)


class ConfigReaderTests(unittest.TestCase):
    def test_config_syntax_result_family(self) -> None:
        from cwo_core.git_store import UnsupportedLayout, parse_config

        data = (b'[core]\n\tautocrlf = input ; comment\n\tbare\n[remote "Origin"]\n\turl = "a b" c\\\n d\n'
                b'[Section.Sub]\n\tKey = "quoted # not a comment"\n\tother = x\\ty\n# trailing\n')
        expected = [
            ("core.autocrlf", "input"), ("core.bare", None), ("remote.Origin.url", "a b c d"),
            ("section.sub.key", "quoted # not a comment"), ("section.sub.other", "x\ty"),
        ]
        rows = (
            ("test_values_are_read_as_git_reads_them", ((data, expected),)),
            ("test_unfamiliar_syntax_is_refused", tuple((value, None) for value in (
                b"[core] bare = true\n", b"key = outside\n", b'[core]\n\tx = "open\n',
                b"[core]\n\tx = a\\qb\n", b"[core\n"))),
        )
        for row_id, examples in rows:
            for value, result in examples:
                with self.subTest(row=row_id, data=value):
                    if result is None:
                        with self.assertRaises(UnsupportedLayout):
                            parse_config(value)
                    else:
                        self.assertEqual(parse_config(value), result)

    def test_booleans_are_read_as_git_reads_them(self) -> None:
        from cwo_core.git_store import UnsupportedLayout, config_bool, config_maybe_bool

        true = (None, "true", "TRUE", "Yes", "on", "1", "2", "-1", "0x10", "010", "1k", "+3", " 7", "2097151k")
        false = ("", "false", "No", "OFF", "0", "0x0", "00", "0k", "-0")
        for value in true:
            self.assertIs(config_bool(value), True, value)
        for value in false:
            self.assertIs(config_bool(value), False, value)
        for value in ("maybe", "true ", "1x", "08", "0x", "- 1", "2147483648", "2097152k", "-2147483648", "1 ", "１"):
            with self.subTest(value=value):
                self.assertIsNone(config_maybe_bool(value))
                with self.assertRaises(UnsupportedLayout):
                    config_bool(value)



class ReferenceReaderTests(unittest.TestCase):
    def test_packed_references_are_read_as_git_reads_them(self) -> None:
        from cwo_core.git_store import UnsupportedLayout, packed_references

        first, second = "a" * 40, "b" * 40
        data = (f"# pack-refs with: peeled fully-peeled sorted \n{first} refs/heads/main\n"
                f"{second} refs/tags/v1\n^{first}\n").encode()
        self.assertEqual(packed_references(data, 20), {"refs/heads/main": first, "refs/tags/v1": second})
        self.assertEqual(packed_references(b"", 20), {})
        for broken in (b"# pack-refs with:\n", b"\n", f"{first} refs/heads/main".encode(), f"^{first}\n".encode(),
                       f"{first} refs/heads/main\n^{first}\n^{first}\n".encode(), f"{first}\trefs/heads/main\n".encode(),
                       f"{first[:-1]} refs/heads/main\n".encode(), f"{first} refs/heads/a.lock\n".encode()):
            with self.subTest(data=broken), self.assertRaises(UnsupportedLayout):
                packed_references(broken, 20)

    def test_reference_names_follow_git(self) -> None:
        from cwo_core.git_store import valid_reference_name

        for name in ("refs/heads/main", "refs/heads/feature/x", "refs/tags/v1.0", "refs/heads/ünïcode"):
            self.assertTrue(valid_reference_name(name), name)
        for name in ("HEAD", "refs/heads/", "refs/heads/a..b", "refs/heads/.hidden", "refs/heads/x.lock", "refs/heads/a b",
                     "refs/heads/a~1", "refs/heads/a^", "refs/heads/a:b", "refs/heads/a?", "refs/heads/a*", "refs/heads/a[",
                     "refs/heads/a\\b", "refs/heads/a@{1}", "refs//heads", "refs/heads/end.", "refs/heads/\x7f"):
            self.assertFalse(valid_reference_name(name), name)


class DeltaTests(unittest.TestCase):
    def test_reconstruction_is_bounded_before_it_is_built(self) -> None:
        import hashlib

        from cwo_core.git_store import CorruptObject

        base = b"a" * 4096
        base_oid, base_raw = blob_entry(base)
        # 256 copies of the whole base: a delta of about 500 bytes that expands to 1 MiB.
        delta = delta_size(4096) + delta_size(1 << 20) + bytes([0xA0, 0x10]) * 256
        target_oid = hashlib.sha1(b"blob 1048576\0" + base * 256).hexdigest()
        with tempfile.TemporaryDirectory() as tmpdir:
            objects = Path(tmpdir)
            write_pack(objects / "pack", [(bytes.fromhex(base_oid), base_raw),
                                          (bytes.fromhex(target_oid), offset_delta_entry(len(base_raw), delta))])
            charges: list[int] = []
            capped = object_store(objects, max_object_bytes=4096, charges=charges)
            with self.assertRaisesRegex(CorruptObject, "object size limit"):
                capped.read(target_oid)
            capped.close()
            self.assertLessEqual(sum(charges), 2 * 4096, "nothing near the expanded size is built or charged")
            charges.clear()
            roomy = object_store(objects, max_object_bytes=2 << 20, charges=charges)
            self.assertEqual(roomy.read(target_oid), ("blob", base * 256))
            roomy.close()
            self.assertIn(1 << 20, charges, "the reconstructed result is charged")

    def test_reconstruction_checks_the_deadline(self) -> None:
        from cwo_core.git_store import apply_delta

        class Deadline(Exception):
            pass

        calls: list[int] = []

        def check_time() -> None:
            calls.append(1)
            if len(calls) > 1:
                raise Deadline

        delta = delta_size(1) + delta_size(10_000) + b"\x01x" * 10_000
        self.assertEqual(apply_delta(b"a", delta, max_size=10_000), b"x" * 10_000)
        with self.assertRaises(Deadline):
            apply_delta(b"a", delta, max_size=10_000, check_time=check_time)

    def test_long_delta_chains_are_followed_without_recursion(self) -> None:
        import hashlib

        content = b"x"
        base_oid, raw = blob_entry(content)
        entries = [(bytes.fromhex(base_oid), raw)]
        offsets = [12]
        position = 12 + len(raw)
        for _ in range(1500):
            following = content + b"!"
            # Copy the whole previous object (two size bytes), then insert one byte.
            delta = delta_size(len(content)) + delta_size(len(following)) + bytes([0xB0, len(content) & 0xFF, len(content) >> 8, 1]) + b"!"
            raw = offset_delta_entry(position - offsets[-1], delta)
            entries.append((hashlib.sha1(f"blob {len(following)}\0".encode() + following).digest(), raw))
            offsets.append(position)
            position += len(raw)
            content = following
        with tempfile.TemporaryDirectory() as tmpdir:
            write_pack(Path(tmpdir) / "pack", entries)
            store = object_store(Path(tmpdir), max_object_bytes=1 << 20)
            self.assertEqual(store.read(entries[-1][0].hex()), ("blob", content))
            store.close()

    def test_copy_and_insert_instructions_are_applied_and_checked(self) -> None:
        from cwo_core.git_store import CorruptObject, apply_delta

        base = b"hello world"
        # source size 11, target size 11: copy "hello " (offset 0, size 6), insert "there"
        delta = bytes([11, 11, 0x90, 6, 5]) + b"there"
        self.assertEqual(apply_delta(base, delta, max_size=64), b"hello there")
        for broken in (bytes([10, 11, 0x90, 6, 5]) + b"there", bytes([11, 12, 0x90, 6, 5]) + b"there",
                       bytes([11, 11, 0x91, 9, 6]), bytes([11, 11, 0])):
            with self.subTest(delta=broken), self.assertRaises(CorruptObject):
                apply_delta(base, broken, max_size=64)

if __name__ == "__main__":
    unittest.main()
