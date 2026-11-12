"""Candidate identity: recording and verifying the exact candidate a closure would claim (issue #37).

Every case uses a temporary Git repository and fake Bead projections. The Beads adapter is replaced by a spy that
answers ``bd show`` and fails on anything else, so a test can assert that a refusal made zero Beads writes.
"""
from __future__ import annotations

import contextlib
import copy
import errno
import hashlib
import importlib.util
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

from cwo_core import candidate_identity as ci  # noqa: E402
from cwo_core import requirement_baseline as rb  # noqa: E402
from tests.real_beads_fixture import configure_git_fixture

FIXTURES = ROOT / "tests" / "fixtures" / "requirement-baseline"
HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None
GIT_ENV = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
GIT_ENV.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, LC_ALL="C")


@contextlib.contextmanager
def native_integer_conversion_limit():
    """Exercise the real decoder with a finite test-only limit, restoring it on exit."""
    previous = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(4300)
        yield
    finally:
        sys.set_int_max_str_digits(previous)


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
         "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args],
        check=True, capture_output=True, text=True, env=GIT_ENV,
    )
    return completed.stdout.strip()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def independent_digest(record: dict) -> str:
    """The documented serialization, computed here rather than by the module."""
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_workspace(parent: Path) -> tuple[Path, str]:
    """A repository with a base commit, one implementation commit and dirty, untracked, excluded and ignored content.

    Returns the repository and its base commit.
    """
    repo = parent / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    configure_git_fixture(repo)
    write(repo / "README.md", "old-name\n")
    write(repo / "LICENSE", "licence text\n")
    write(repo / "src" / "tool.py", "print('old-name')\n")
    write(repo / "docs" / "guide.md", "# old-name\n")
    write(repo / "docs" / "index.md", "index\n")
    write(repo / ".gitignore", "build/\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")
    write(repo / "src" / "tool.py", "print('new-name')\n")
    git(repo, "commit", "-q", "-am", "implement")
    write(repo / "docs" / "guide.md", "# new-name\n")  # modified, uncommitted
    (repo / "src" / "tool.py").chmod(0o755)  # mode change only
    write(repo / "src" / "new.py", "NEW = 'new-name'\n")  # untracked
    (repo / "src" / "link").symlink_to("tool.py")  # untracked symlink
    (repo / "LICENSE").unlink()  # deleted
    write(repo / "evidence" / "run.txt", "test log\n")  # untracked, excluded
    write(repo / "build" / "out.bin", "ignored\n")  # ignored
    return repo, base


def bead(bead_id: str, *texts: str) -> dict:
    """A fake ``bd show --json --include-comments`` projection."""
    return {
        "id": bead_id,
        "status": "in_progress",
        "comments": [{"id": index + 1, "author": "lead", "text": text} for index, text in enumerate(texts)],
    }


class BeadsSpy:
    """Stands in for the Beads adapter: answers ``bd show`` with a projection and refuses every other command."""

    def __init__(self, projection: dict | None = None) -> None:
        self.projection = projection
        self.calls: list[list[str]] = []

    def run_bd(self, args: list[str], timeout: int | None = None) -> str:
        self.calls.append(list(args))
        if args[:1] == ["show"] and self.projection is not None:
            return json.dumps([self.projection])
        raise AssertionError(f"a candidate identity check ran a Beads command other than show: {args}")

    def run_bd_structured(self, args: object, **kwargs: object) -> None:
        self.calls.append(list(args))  # type: ignore[arg-type]
        raise AssertionError("a candidate identity check used the structured Beads adapter")

    @contextlib.contextmanager
    def installed(self):
        with patch("cwo_core.beads.run_bd", side_effect=self.run_bd), \
                patch("cwo_core.beads.run_bd_structured", side_effect=self.run_bd_structured):
            yield self

    def writes(self) -> list[list[str]]:
        return [call for call in self.calls if call[:1] != ["show"]]


class WorkspaceTestCase(unittest.TestCase):
    SCOPE = ["docs", "src"]
    EXCLUDED = ["evidence"]

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.tmp = Path(directory.name)
        self.repo, self.base = make_workspace(self.tmp)
        self.baseline = fixture("baseline-v1.json")
        self.amendment = fixture("amendment-adds-criterion.json")
        self.chain = rb.resolve_chain(self.baseline)
        self.amended = rb.resolve_chain(self.baseline, [self.amendment])
        self.baseline_lines = [rb.reference_line("proj-abc", entry["version"], entry["digest"])
                               for entry in self.amended["baselines"]]

    def capture(self, repo: Path | None = None, chain: dict | None = None, **overrides: object) -> dict:
        options = {"base_commit": self.base, "scope_paths": self.SCOPE, "excluded_paths": self.EXCLUDED}
        options.update(overrides)
        return ci.capture_candidate(repo or self.repo, chain=chain or self.chain, **options)

    def refused_capture(self, repo: Path | None = None, **overrides: object) -> str:
        with self.assertRaises(ci.CandidateIdentityError) as caught:
            self.capture(repo, **overrides)
        return str(caught.exception)

    def line(self, record: dict) -> str:
        return ci.candidate_reference_line(record["bead_id"], independent_digest(record))


class CandidateRecordTests(WorkspaceTestCase):
    def test_the_record_names_the_commit_tree_baseline_and_every_dirty_or_untracked_file(self) -> None:
        record = self.capture()
        self.assertEqual(ci.candidate_errors(record), [])
        self.assertEqual(record["bead_id"], "proj-abc")
        self.assertEqual(record["baseline"], {"version": 1, "digest": independent_digest(self.baseline)})
        self.assertEqual(record["commit"], git(self.repo, "rev-parse", "HEAD"))
        self.assertEqual(record["tree"], git(self.repo, "rev-parse", "HEAD^{tree}"))
        self.assertEqual(record["base_commit"], self.base)
        self.assertEqual(record["repository"], {"root_commits": [self.base]})
        self.assertEqual(record["delivery_scope"], {"paths": ["docs", "src"], "live_resources": []})
        self.assertEqual(record["excluded_paths"], ["evidence"])
        self.assertEqual(record["worktree_manifest"], [
            {"path": "LICENSE", "change": "deleted", "type": "absent", "mode": None, "size": None, "sha256": None},
            {"path": "docs/guide.md", "change": "modified", "type": "file", "mode": "100644", "size": 11,
             "sha256": sha(b"# new-name\n")},
            {"path": "src/link", "change": "added", "type": "symlink", "mode": "120000", "size": 7,
             "sha256": sha(b"tool.py")},
            {"path": "src/new.py", "change": "added", "type": "file", "mode": "100644", "size": 17,
             "sha256": sha(b"NEW = 'new-name'\n")},
            {"path": "src/tool.py", "change": "modified", "type": "file", "mode": "100755", "size": 18,
             "sha256": sha(b"print('new-name')\n")},
        ])

    def test_the_digest_reference_line_and_binding_use_the_documented_serialization(self) -> None:
        record = self.capture()
        digest = independent_digest(record)
        self.assertEqual(ci.candidate_digest(record), digest)
        self.assertEqual(ci.candidate_binding(record), digest)
        self.assertEqual(ci.candidate_reference_line("proj-abc", digest), f"cwo-candidate-identity bead=proj-abc digest={digest}")
        with self.assertRaises(ci.CandidateIdentityError):
            ci.candidate_binding({**record, "version": 2})

    def test_capture_refuses_a_scope_path_that_is_not_in_the_candidate(self) -> None:
        for path in ("src/absent.py", "LICENSE", "build/out.bin", "build"):
            with self.subTest(path=path):
                self.assertIn(f"delivery scope path {path} is not in the candidate",
                              self.refused_capture(scope_paths=["src", path]))
        self.assertEqual(self.capture(scope_paths=["."])["delivery_scope"]["paths"], ["."])
        self.assertEqual(self.capture(scope_paths=["src/new.py"])["delivery_scope"]["paths"], ["src/new.py"])

    def test_capture_refuses_a_base_that_is_not_an_ancestor_or_not_a_commit(self) -> None:
        clone = self.tmp / "side"
        git(self.tmp, "clone", "-q", str(self.repo), str(clone))
        configure_git_fixture(clone)
        git(clone, "checkout", "-q", "-b", "side", self.base)
        write(clone / "side.txt", "side\n")
        git(clone, "add", "side.txt")
        git(clone, "commit", "-q", "-m", "side")
        side = git(clone, "rev-parse", "HEAD")
        git(self.repo, "fetch", "-q", str(clone), "side")
        self.assertIn("is not an ancestor of the candidate commit", self.refused_capture(base_commit=side))
        self.assertIn("is not a commit", self.refused_capture(base_commit="0" * 40))
        self.assertIn("must name a commit", self.refused_capture(base_commit="--all"))
        self.assertIn("is not a commit", self.refused_capture(base_commit=git(self.repo, "rev-parse", "HEAD^{tree}")))

    def test_capture_refuses_a_missing_repository_a_plain_directory_or_a_subdirectory(self) -> None:
        self.assertIn("does not exist", self.refused_capture(repo=self.tmp / "missing"))
        plain = self.tmp / "plain"
        plain.mkdir()
        self.assertIn("is not a Git working tree", self.refused_capture(repo=plain))
        self.assertIn("is not the top of its Git working tree", self.refused_capture(repo=self.repo / "src"))

    def test_a_delivery_scope_that_names_live_resources_is_refused_until_an_observation_binding_exists(self) -> None:
        resource = {"resource": "legacy-sync.service", "required_state": "inactive and disabled"}
        message = self.refused_capture(live_resources=[resource])
        self.assertIn("cannot bind independently observed live-resource state", message)
        self.assertIn("evidence-bound adjudication", message)
        record = self.capture()
        record["delivery_scope"]["live_resources"] = [resource]
        self.assertIn(ci.LIVE_RESOURCE_REFUSAL, ci.candidate_errors(record))

    def test_capture_refuses_content_it_cannot_identify(self) -> None:
        nested = self.repo / "src" / "vendored"
        nested.mkdir()
        git(nested, "init", "-q")
        configure_git_fixture(nested)
        write(nested / "a.txt", "a\n")
        git(nested, "add", "a.txt")
        git(nested, "commit", "-q", "-m", "nested")
        self.assertIn("nested repository", self.refused_capture())
        shutil.rmtree(nested)
        (self.repo / "docs" / "index.md").unlink()
        os.mkfifo(self.repo / "docs" / "index.md")
        self.assertIn("neither a regular file nor a symlink", self.refused_capture())

    def test_capture_refuses_exclusions_that_could_hide_tracked_or_delivered_content(self) -> None:
        self.assertIn("only untracked content can be excluded", self.refused_capture(excluded_paths=["docs/guide.md"]))
        self.assertIn("only untracked content can be excluded", self.refused_capture(excluded_paths=["evidence", "docs"]))
        write(self.repo / "src" / "generated" / "out.py", "x\n")
        self.assertIn("covers delivery scope path", self.refused_capture(
            scope_paths=["src/generated/out.py"], excluded_paths=["src/generated"]))
        self.assertIn("name at least one delivery scope path", self.refused_capture(scope_paths=[]))
        self.assertIn("'..' component", self.refused_capture(excluded_paths=["../evidence"]))

    def test_result_and_approval_fields_are_refused(self) -> None:
        record = self.capture()
        for key, value, expected in (
            ("status", "passed", "not whether it passed"),
            ("results", [], "not whether it passed"),
            ("approved_by", "architect", "does not authenticate who approved"),
            ("signature", "abc", "does not authenticate who approved"),
        ):
            with self.subTest(key=key):
                self.assertIn(expected, "\n".join(ci.candidate_errors({**record, key: value})))
        entry = copy.deepcopy(record)
        entry["worktree_manifest"][0]["verdict"] = "ok"
        self.assertIn("not whether it passed", "\n".join(ci.candidate_errors(entry)))

    def test_malformed_records_are_refused(self) -> None:
        record = self.capture()
        long_oid = "a" * 64

        def edit(path: str, value: object):
            def apply(target: dict) -> None:
                keys = path.split(".")
                for key in keys[:-1]:
                    target = target[int(key)] if key.isdigit() else target[key]
                last = keys[-1]
                if value is KeyError:
                    del target[last]
                elif last.isdigit():
                    target[int(last)] = value
                else:
                    target[last] = value
            return apply

        cases = {
            "version 2": edit("version", 2),
            "version true": edit("version", True),
            "record type": edit("record_type", "cwo-requirement-baseline"),
            "bead id": edit("bead_id", "proj abc"),
            "baseline digest": edit("baseline.digest", "sha256:00"),
            "baseline version": edit("baseline.version", 0),
            "baseline extra": edit("baseline.amendment", "x"),
            "short commit": edit("commit", "abc1234"),
            "upper tree": edit("tree", record["tree"].upper()),
            "mixed hashes": edit("commit", long_oid),
            "no roots": edit("repository.root_commits", []),
            "root not oid": edit("repository.root_commits", ["main"]),
            "no scope": edit("delivery_scope.paths", []),
            "parent scope": edit("delivery_scope.paths", ["../outside"]),
            "absolute scope": edit("delivery_scope.paths", ["/etc"]),
            "empty component": edit("delivery_scope.paths", ["docs//guide.md"]),
            "dot component": edit("delivery_scope.paths", ["docs/./guide.md"]),
            "control scope": edit("delivery_scope.paths", ["docs\x1b[2J"]),
            "unsorted scope": edit("delivery_scope.paths", ["src", "docs"]),
            "excluded covers scope": edit("excluded_paths", ["src"]),
            "excluded whole": edit("excluded_paths", ["."]),
            "missing manifest": edit("worktree_manifest", KeyError),
            "deleted with digest": edit("worktree_manifest.0.sha256", "0" * 64),
            "absent but added": edit("worktree_manifest.0.change", "added"),
            "file with link mode": edit("worktree_manifest.1.mode", "120000"),
            "symlink with file mode": edit("worktree_manifest.2.mode", "100644"),
            "negative size": edit("worktree_manifest.1.size", -1),
            "bad digest": edit("worktree_manifest.1.sha256", "xyz"),
            "unsorted manifest": edit("worktree_manifest.0", record["worktree_manifest"][4]),
            "added under exclusion": edit("worktree_manifest.3.path", "evidence/new.py"),
        }
        for name, apply in cases.items():
            with self.subTest(case=name):
                changed = copy.deepcopy(record)
                apply(changed)
                self.assertTrue(ci.candidate_errors(changed), name)
        self.assertTrue(ci.candidate_errors([]))
        self.assertTrue(ci.candidate_errors(None))


class VerificationTests(WorkspaceTestCase):

    def test_drift_in_dirty_untracked_or_clean_content_is_refused(self) -> None:
        mutations = {
            "dirty file edited": (lambda repo: write(repo / "docs" / "guide.md", "# new-name, v2\n"),
                                  "docs/guide.md changed since the candidate was recorded (size, sha256)"),
            "same-size edit": (lambda repo: write(repo / "docs" / "guide.md", "# NEW-NAME\n"),
                               "docs/guide.md changed since the candidate was recorded (sha256)"),
            "untracked file added": (lambda repo: write(repo / "src" / "extra.py", "x\n"),
                                     "src/extra.py is dirty or untracked now (added) but is not in the candidate"),
            "clean file edited": (lambda repo: write(repo / "docs" / "index.md", "changed\n"),
                                  "docs/index.md is dirty or untracked now (modified)"),
            "clean file deleted": (lambda repo: (repo / "README.md").unlink(),
                                   "README.md is dirty or untracked now (deleted)"),
            "dirty file reverted": (lambda repo: git(repo, "checkout", "--", "docs/guide.md"),
                                    "docs/guide.md was dirty or untracked in the candidate and is not now"),
            "deleted file restored": (lambda repo: git(repo, "checkout", "--", "LICENSE"),
                                      "LICENSE was dirty or untracked in the candidate and is not now"),
            "mode changed": (lambda repo: (repo / "src" / "tool.py").chmod(0o644),
                             "src/tool.py was dirty or untracked in the candidate and is not now"),
            "symlink retargeted": (lambda repo: ((repo / "src" / "link").unlink(), (repo / "src" / "link").symlink_to("new.py")),
                                   "src/link changed since the candidate was recorded (size, sha256)"),
            "symlink replaced by file": (lambda repo: ((repo / "src" / "link").unlink(), write(repo / "src" / "link", "tool.py")),
                                         "src/link changed since the candidate was recorded (type, mode)"),
        }
        for name, (mutate, expected) in mutations.items():
            with self.subTest(mutation=name):
                parent = Path(tempfile.mkdtemp(dir=self.tmp))
                repo, base = make_workspace(parent)
                record = self.capture(repo=repo, base_commit=base)
                mutate(repo)
                self.assertIn(expected, "\n".join(ci.verify_candidate(record, repo)))


    def test_a_tampered_record_is_refused(self) -> None:
        record = self.capture()
        cases = {
            "commit": (lambda value: value.update(commit=self.base), "not the candidate commit"),
            "tree": (lambda value: value.update(tree=git(self.repo, "rev-parse", f"{self.base}^{{tree}}")), "not the candidate tree"),
            "digest": (lambda value: value["worktree_manifest"][1].update(sha256="0" * 64), "docs/guide.md changed"),
            "omitted entry": (lambda value: value["worktree_manifest"].pop(3), "src/new.py is dirty or untracked now"),
            "invented entry": (lambda value: value["worktree_manifest"].append(
                {"path": "zz.txt", "change": "added", "type": "file", "mode": "100644", "size": 0, "sha256": sha(b"")}),
                "zz.txt was dirty or untracked in the candidate and is not now"),
        }
        for name, (tamper, expected) in cases.items():
            with self.subTest(case=name):
                changed = copy.deepcopy(record)
                tamper(changed)
                self.assertIn(expected, "\n".join(ci.verify_candidate(changed, self.repo)))

    def test_verification_writes_nothing_to_the_repository(self) -> None:
        def snapshot() -> dict[str, str]:
            files = {}
            for path in sorted(self.repo.rglob("*")):
                if path.is_file() and not path.is_symlink() and not path.is_fifo():
                    files[path.relative_to(self.repo).as_posix()] = sha(path.read_bytes())
            return files

        record = self.capture()
        before = snapshot()
        self.assertIn(".git/index", before)
        self.assertEqual(ci.verify_candidate(record, self.repo), [])
        write(self.repo / "src" / "extra.py", "x\n")
        self.assertTrue(ci.verify_candidate(record, self.repo))
        (self.repo / "src" / "extra.py").unlink()
        self.capture()
        self.assertEqual(snapshot(), before)

    def test_a_new_commit_or_another_head_is_refused(self) -> None:
        record = self.capture()
        git(self.repo, "add", "-A", "docs", "src", "LICENSE")
        git(self.repo, "commit", "-q", "-m", "deliver")
        errors = "\n".join(ci.verify_candidate(record, self.repo))
        self.assertIn(f"HEAD is {git(self.repo, 'rev-parse', 'HEAD')}, not the candidate commit {record['commit']}", errors)
        self.assertIn("not the candidate tree", errors)
        git(self.repo, "reset", "-q", "--soft", self.base)
        self.assertIn(f"HEAD is {self.base}", "\n".join(ci.verify_candidate(record, self.repo)))

    def test_a_working_tree_in_another_repository_is_refused(self) -> None:
        record = self.capture()
        other = self.tmp / "other"
        shutil.copytree(self.repo, other, symlinks=True, ignore=shutil.ignore_patterns(".git", "evidence"))
        git(other, "init", "-q")
        configure_git_fixture(other)
        git(other, "add", "-A")
        git(other, "commit", "-q", "-m", "unrelated")
        errors = "\n".join(ci.verify_candidate({**record, "base_commit": git(other, "rev-parse", "HEAD")}, other))
        self.assertIn("belongs to another repository", errors)
        self.assertIn("cannot be identified again", "\n".join(ci.verify_candidate(record, other)))


    def test_an_unchanged_working_tree_verifies(self) -> None:
        record = self.capture()
        self.assertEqual(ci.verify_candidate(record, self.repo), [])
        write(self.repo / "evidence" / "later.txt", "a later log is excluded\n")
        self.assertEqual(ci.verify_candidate(record, self.repo), [])


class BaselineAndBeadTests(WorkspaceTestCase):
    def check(self, record: dict | None, projection: dict | None, chain: dict | None = None) -> dict:
        spy = BeadsSpy()
        with spy.installed():
            result = ci.check_candidate(record, root=self.repo, chain=chain or self.chain, bead=projection)
        self.assertEqual(spy.calls, [])
        return result

    def errors(self, record: dict | None, projection: dict | None, chain: dict | None = None) -> str:
        result = self.check(record, projection, chain)
        self.assertFalse(result["valid"])
        return "\n".join(result["errors"])

    def test_absence_is_refused(self) -> None:
        record = self.capture()
        self.assertIn("no candidate identity was supplied", self.errors(None, bead("proj-abc", self.baseline_lines[0])))
        self.assertIn("no Bead projection was supplied", self.errors(record, None))
        shutil.rmtree(self.repo)
        self.assertIn("does not exist", self.errors(record, bead("proj-abc", self.baseline_lines[0], self.line(record))))

    def test_a_current_candidate_recorded_after_its_baseline_is_accepted(self) -> None:
        record = self.capture()
        result = self.check(record, bead("proj-abc", "claimed", self.baseline_lines[0], "work started", self.line(record)))
        self.assertEqual(result["errors"], [])
        self.assertTrue(result["valid"])
        self.assertEqual(result["digest"], independent_digest(record))
        self.assertEqual(result["reference_line"], self.line(record))

    def test_a_candidate_for_an_older_baseline_version_is_stale(self) -> None:
        record = self.capture()
        projection = bead("proj-abc", self.baseline_lines[0], self.line(record), self.baseline_lines[1])
        errors = self.errors(record, projection, chain=self.amended)
        self.assertIn("recorded against baseline version 1, but the baseline is now version 2", errors)
        self.assertIn("it is stale", errors)
        current = self.capture(chain=self.amended)
        self.assertEqual(self.check(current, bead("proj-abc", *self.baseline_lines, self.line(current)), self.amended)["errors"], [])

    def test_candidate_reference_refusal_family(self) -> None:
        # One real read-only capture supplies the retained baseline-chain rows;
        # every projection/record is private.
        record = self.capture()
        replacement = rb.reference_line("proj-abc", 1, "sha256:" + "4" * 64)
        rows = (
            ("test_the_baseline_chain_on_the_bead_is_checked_as_well", "baseline-absent", record,
             bead("proj-abc", self.line(record)),
             ("baseline version 1 (" + independent_digest(self.baseline) + ") is not recorded on proj-abc",
              "which the candidate claims, is not recorded")),
            ("test_the_baseline_chain_on_the_bead_is_checked_as_well", "baseline-diverged", record,
             bead("proj-abc", self.baseline_lines[0], replacement, self.line(record)), ("replaced or diverged",)),
            ("test_the_baseline_chain_on_the_bead_is_checked_as_well", "foreign-projection", record,
             bead("proj-xyz", self.baseline_lines[0], self.line(record)), ("not 'proj-abc'",)),
        )
        for row_id, case, candidate, projection, expected_errors in rows:
            with self.subTest(row=row_id, case=case):
                errors = self.errors(copy.deepcopy(candidate), copy.deepcopy(projection))
                for expected in expected_errors:
                    self.assertIn(expected, errors)


    def test_a_superseded_candidate_is_refused(self) -> None:
        record = self.capture()
        later = ci.candidate_reference_line("proj-abc", "sha256:" + "2" * 64)
        errors = self.errors(record, bead("proj-abc", self.baseline_lines[0], self.line(record), later))
        self.assertIn("records a later candidate sha256:" + "2" * 64, errors)
        self.assertIn("is not the current one", errors)
        again = bead("proj-abc", self.baseline_lines[0], self.line(record), later, self.line(record))
        self.assertEqual(self.check(record, again)["errors"], [])


    def test_malformed_embedded_or_foreign_candidate_references_are_refused(self) -> None:
        record = self.capture()
        line = self.line(record)
        cases = {
            "malformed": ("cwo-candidate-identity bead=proj-abc digest=sha256:00", "starts like a candidate reference"),
            "after a note": ("Verified locally.\n" + ci.candidate_reference_line("proj-abc", "sha256:" + "5" * 64),
                             "starts like a candidate reference"),
            "inside text": ("superseded by " + ci.candidate_reference_line("proj-abc", "sha256:" + "3" * 64),
                            "contains a candidate reference inside other text"),
            "other case": (line.upper(), "starts like a candidate reference"),
            "foreign bead": (ci.candidate_reference_line("proj-xyz", independent_digest(record)),
                             "records a candidate for Bead proj-xyz on proj-abc"),
        }
        for name, (text, expected) in cases.items():
            with self.subTest(case=name):
                self.assertIn(expected, self.errors(record, bead("proj-abc", self.baseline_lines[0], line, text)))
        prose = "the cwo-candidate-identity record is attached to the review"
        self.assertEqual(self.check(record, bead("proj-abc", self.baseline_lines[0], line, prose))["errors"], [])

    def test_a_candidate_for_another_baseline_or_bead_is_refused(self) -> None:
        record = self.capture()
        replaced = copy.deepcopy(record)
        replaced["baseline"]["digest"] = "sha256:" + "1" * 64
        self.assertIn("which is not in this baseline chain",
                      self.errors(replaced, bead("proj-abc", self.baseline_lines[0], self.line(replaced))))
        other = copy.deepcopy(record)
        other["bead_id"] = "proj-xyz"
        self.assertIn("the candidate is for Bead 'proj-xyz', not 'proj-abc'",
                      self.errors(other, bead("proj-abc", self.baseline_lines[0], self.line(other))))

    def test_a_candidate_not_recorded_on_the_bead_is_refused(self) -> None:
        record = self.capture()
        self.assertIn(f"candidate {independent_digest(record)} is not recorded on proj-abc",
                      self.errors(record, bead("proj-abc", self.baseline_lines[0])))

    def test_a_candidate_recorded_before_its_baseline_is_refused(self) -> None:
        record = self.capture()
        self.assertIn("was recorded on proj-abc before baseline version 1",
                      self.errors(record, bead("proj-abc", self.line(record), self.baseline_lines[0])))


class CommandLineTests(WorkspaceTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.baseline_path = self.tmp / "baseline.json"
        self.baseline_path.write_text(json.dumps(self.baseline), encoding="utf-8")
        self.output = self.tmp / "candidate.json"

    def run_cli(self, *argv: str, spy: BeadsSpy | None = None) -> tuple[int, dict, BeadsSpy]:
        from candidate_identity import main

        spy = spy or BeadsSpy()
        stdout, stderr = io.StringIO(), io.StringIO()
        with spy.installed(), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(list(argv))
        try:
            payload = json.loads(stdout.getvalue())
        except json.JSONDecodeError:
            payload = {"stdout": stdout.getvalue(), "stderr": stderr.getvalue()}
        return code, payload, spy

    def record(self, *extra: str) -> tuple[int, dict, BeadsSpy]:
        return self.run_cli("record", "--repo", str(self.repo), "--baseline", str(self.baseline_path), "--base-commit",
                            self.base, "--scope", "src", "--scope", "docs", "--exclude", "evidence", "--json", *extra)

    def verify(self, *extra: str, spy: BeadsSpy | None = None) -> tuple[int, dict, BeadsSpy]:
        return self.run_cli("verify", "--repo", str(self.repo), "--baseline", str(self.baseline_path), "--candidate",
                            str(self.output), "--json", *extra, spy=spy)

    def record_utf8_candidate(self) -> tuple[Path, Path]:
        baseline = copy.deepcopy(self.baseline)
        baseline["criteria"][0]["requirement"] += " Le café reste lisible."
        amendment = copy.deepcopy(self.amendment)
        amendment["baseline"]["criteria"][0] = copy.deepcopy(baseline["criteria"][0])
        amendment["prior_digest"] = independent_digest(baseline)
        amendment["rationale"] = "Ajout après révision."
        self.assertEqual(rb.baseline_errors(baseline), [])
        self.assertEqual(rb.amendment_errors(baseline, amendment), [])
        self.baseline_path.write_text(json.dumps(baseline, ensure_ascii=False), encoding="utf-8")
        amendment_path = self.tmp / "utf8-amendment.json"
        amendment_path.write_text(json.dumps(amendment, ensure_ascii=False), encoding="utf-8")
        chain = rb.resolve_chain(baseline, [amendment])
        code, payload, record_spy = self.record(
            "--amendment", str(amendment_path), "--output", str(self.output),
        )
        self.assertEqual((code, payload["errors"]), (0, []))
        written = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(payload["digest"], independent_digest(written))
        self.assertEqual(payload["baseline"], {"version": 2, "digest": chain["digest"]})
        self.assertIn("café".encode("utf-8"), self.baseline_path.read_bytes())
        lines = [
            rb.reference_line("proj-abc", entry["version"], entry["digest"]) for entry in chain["baselines"]
        ]
        projection = self.tmp / "utf8-bead.json"
        projection.write_text(
            json.dumps([bead("proj-abc", *lines, payload["reference_line"])], ensure_ascii=False), encoding="utf-8",
        )
        code, result, verify_spy = self.verify("--amendment", str(amendment_path), "--bead-json", str(projection))
        self.assertEqual((code, result["errors"]), (0, []))
        self.assertIs(result["valid"], True)
        self.assertEqual(result["digest"], payload["digest"])
        self.assertEqual(record_spy.calls + verify_spy.calls, [])
        return amendment_path, projection

    def test_native_integer_failures_refuse_before_capture_projection_or_write(self) -> None:
        import candidate_identity as cli

        code, payload, positive_spy = self.record("--output", str(self.output))
        self.assertEqual((code, payload["errors"]), (0, []))
        projection = self.tmp / "parser-bead.json"
        projection.write_text(
            json.dumps([bead("proj-abc", self.baseline_lines[0], payload["reference_line"])]), encoding="utf-8",
        )
        code, result, verify_spy = self.verify("--bead-json", str(projection))
        self.assertEqual((code, result["errors"]), (0, []))
        self.assertEqual(positive_spy.calls + verify_spy.calls, [])
        invalid = self.tmp / "native-integer.json"
        invalid.write_text('{"version": ' + "9" * 4400 + "}", encoding="utf-8")
        refused_output = self.tmp / "parser-refused-candidate.json"
        record_args = [
            "--repo", str(self.repo), "--base-commit", self.base,
            "--scope", "src", "--scope", "docs", "--exclude", "evidence",
            "--output", str(refused_output), "--json",
        ]
        cases = (
            ("baseline", ["record", *record_args, "--baseline", str(invalid)], "recorded"),
            ("amendment", ["record", *record_args, "--baseline", str(self.baseline_path),
                           "--amendment", str(invalid)], "recorded"),
            ("candidate", ["verify", "--repo", str(self.repo), "--baseline", str(self.baseline_path),
                           "--candidate", str(invalid), "--bead-json", str(projection), "--json"], "valid"),
            ("candidate-beads", ["verify", "--repo", str(self.repo), "--baseline", str(self.baseline_path),
                                 "--candidate", str(invalid), "--read-beads", "--json"], "valid"),
        )
        original_open = Path.open
        writes: list[tuple[str, str]] = []

        def watched_open(path: Path, mode: str = "r", *args: object, **kwargs: object):
            if any(flag in mode for flag in "wax+"):
                writes.append((str(path), mode))
            return original_open(path, mode, *args, **kwargs)

        for name, argv, field in cases:
            with self.subTest(consumer=name):
                spy = BeadsSpy()
                stdout, stderr = io.StringIO(), io.StringIO()
                with patch.object(cli, "capture_candidate", wraps=cli.capture_candidate) as capture, \
                        patch.object(cli, "_bead_projection", wraps=cli._bead_projection) as projection_read, \
                        patch.object(cli, "check_candidate", wraps=cli.check_candidate) as check, \
                        patch.object(Path, "open", autospec=True, side_effect=watched_open), spy.installed(), \
                        contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    with native_integer_conversion_limit():
                        code = cli.main(argv)
                    self.assertEqual(code, 1)
                    result = json.loads(stdout.getvalue())
                    self.assertIs(result[field], False)
                    self.assertIsInstance(result["errors"], list)
                    self.assertEqual(len(result["errors"]), 1)
                    self.assertTrue(result["errors"][0].startswith("not JSON: "))
                    self.assertEqual(stderr.getvalue(), "")
                    capture.assert_not_called()
                    projection_read.assert_not_called()
                    check.assert_not_called()
                    self.assertEqual(spy.calls, [])
                    self.assertEqual(writes, [])
                    self.assertFalse(refused_output.exists())

    def test_utf8_file_refusals_precede_candidate_effects(self) -> None:
        import candidate_identity as cli

        amendment_path, projection = self.record_utf8_candidate()
        invalid = self.tmp / "invalid-utf8.json"
        invalid.write_bytes(b'{"version":"\xff"}')
        refused_output = self.tmp / "utf8-refused-candidate.json"
        record_args = [
            "--repo", str(self.repo), "--base-commit", self.base,
            "--scope", "src", "--scope", "docs", "--exclude", "evidence",
            "--amendment", str(amendment_path), "--output", str(refused_output), "--json",
        ]
        verify_args = [
            "--repo", str(self.repo), "--baseline", str(self.baseline_path),
            "--candidate", str(invalid), "--amendment", str(amendment_path), "--json",
        ]
        cases = (
            ("baseline", ["record", *record_args, "--baseline", str(invalid)], "recorded"),
            ("amendment", ["record", *record_args, "--baseline", str(self.baseline_path),
                           "--amendment", str(invalid)], "recorded"),
            ("candidate-saved", ["verify", *verify_args, "--bead-json", str(projection)], "valid"),
            ("candidate-beads", ["verify", *verify_args, "--read-beads"], "valid"),
        )
        original_open = Path.open

        for name, argv, field in cases:
            with self.subTest(consumer=name):
                writes: list[tuple[str, str]] = []
                spy = BeadsSpy()
                stdout, stderr = io.StringIO(), io.StringIO()

                def watch_utf8_input_open(path: Path, mode: str = "r", *args: object, **kwargs: object):
                    if any(flag in mode for flag in "wax+"):
                        writes.append((str(path), mode))
                    return original_open(path, mode, *args, **kwargs)

                with patch.object(cli, "capture_candidate", wraps=cli.capture_candidate) as capture, \
                        patch.object(cli, "_bead_projection", wraps=cli._bead_projection) as projection_read, \
                        patch.object(cli, "check_candidate", wraps=cli.check_candidate) as check, \
                        patch.object(Path, "open", autospec=True, side_effect=watch_utf8_input_open), spy.installed(), \
                        contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    failure = None
                    code = None
                    try:
                        code = cli.main(argv)
                    except UnicodeDecodeError as exc:
                        failure = exc
                    capture.assert_not_called()
                    projection_read.assert_not_called()
                    check.assert_not_called()
                    self.assertEqual(spy.calls, [])
                    self.assertEqual(writes, [])
                    self.assertFalse(refused_output.exists())
                    self.assertIsNone(failure, "invalid UTF-8 input must produce structured refusal JSON")
                    self.assertEqual(code, 1)
                    result = json.loads(stdout.getvalue())
                    self.assertEqual(set(result), {field, "errors"})
                    self.assertIs(result[field], False)
                    self.assertEqual(len(result["errors"]), 1)
                    self.assertTrue(result["errors"][0].startswith(f"cannot read input {invalid}: "))
                    self.assertIn("utf-8", result["errors"][0])
                    self.assertEqual(stderr.getvalue(), "")

    def test_record_then_verify_against_a_saved_projection(self) -> None:
        code, payload, spy = self.record("--output", str(self.output))
        self.assertEqual((code, payload["errors"]), (0, []))
        written = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(payload["digest"], independent_digest(written))
        self.assertEqual(payload["reference_line"], self.line(written))
        projection = self.tmp / "bead.json"
        projection.write_text(json.dumps([bead("proj-abc", self.baseline_lines[0], payload["reference_line"])]), encoding="utf-8")
        code, result, verify_spy = self.verify("--bead-json", str(projection))
        self.assertEqual((code, result["errors"]), (0, []))
        self.assertEqual(result["digest"], payload["digest"])
        self.assertEqual(spy.calls + verify_spy.calls, [])

    def test_verify_reads_the_bead_with_show_only_and_refuses_drift_without_writing(self) -> None:
        self.assertEqual(self.record("--output", str(self.output))[0], 0)
        line = self.line(json.loads(self.output.read_text(encoding="utf-8")))
        spy = BeadsSpy(bead("proj-abc", self.baseline_lines[0], line))
        code, result, _ = self.verify("--read-beads", spy=spy)
        self.assertEqual((code, result["errors"]), (0, []))
        write(self.repo / "src" / "new.py", "NEW = 'changed after recording'\n")
        code, result, _ = self.verify("--read-beads", spy=spy)
        self.assertEqual(code, 1)
        self.assertIn("src/new.py changed since the candidate was recorded", "\n".join(result["errors"]))
        spy.projection = bead("proj-abc", self.baseline_lines[0])
        self.assertEqual(self.verify("--read-beads", spy=spy)[0], 1)
        self.assertEqual(spy.writes(), [])
        self.assertEqual(spy.calls, [["show", "--json", "--include-comments", "--", "proj-abc"]] * 3)

    def test_input_oserror_keeps_its_existing_diagnostic(self) -> None:
        import candidate_identity as cli

        missing = self.tmp / "missing-baseline.json"
        with patch.object(cli, "capture_candidate", wraps=cli.capture_candidate) as capture:
            code, payload, spy = self.record(
                "--baseline", str(missing), "--output", str(self.output),
            )
            capture.assert_not_called()
            self.assertEqual(spy.calls, [])
            self.assertEqual(code, 1)
            self.assertEqual(set(payload), {"recorded", "errors"})
            self.assertIs(payload["recorded"], False)
            self.assertTrue(payload["errors"][0].startswith("cannot read input: "))
            self.assertIn(str(missing), payload["errors"][0])
            self.assertFalse(self.output.exists())

    def test_record_refusals_write_nothing(self) -> None:
        self.output.write_text("existing\n", encoding="utf-8")
        code, payload, _ = self.record("--output", str(self.output))
        self.assertEqual(code, 1)
        self.assertIn("already exists", "\n".join(payload["errors"]))
        self.assertEqual(self.output.read_text(encoding="utf-8"), "existing\n")
        inside = self.repo / "candidate.json"
        code, payload, _ = self.record("--output", str(inside))
        self.assertEqual(code, 1)
        self.assertIn("would change the candidate it records", "\n".join(payload["errors"]))
        self.assertFalse(inside.exists())
        code, payload, _ = self.record("--output", str(self.tmp / "other.json"), "--scope", "missing")
        self.assertEqual(code, 1)
        self.assertFalse((self.tmp / "other.json").exists())
        excluded = self.repo / "evidence" / "candidate.json"
        self.assertEqual(self.record("--output", str(excluded))[0], 0)
        self.output.unlink()
        self.output.write_text(excluded.read_text(encoding="utf-8"), encoding="utf-8")
        projection = self.tmp / "bead.json"
        projection.write_text(json.dumps(bead("proj-abc", self.baseline_lines[0], self.line(json.loads(excluded.read_text())))),
                              encoding="utf-8")
        self.assertEqual(self.verify("--bead-json", str(projection))[0], 0)

    def test_verify_needs_exactly_one_bead_source(self) -> None:
        self.assertEqual(self.record("--output", str(self.output))[0], 0)
        for extra in ((), ("--read-beads", "--bead-json", "x.json")):
            with self.subTest(extra=extra), self.assertRaises(SystemExit) as raised:
                self.verify(*extra)
            self.assertEqual(raised.exception.code, 2)

    def test_an_unreadable_bead_is_a_refusal(self) -> None:
        self.assertEqual(self.record("--output", str(self.output))[0], 0)

        class Failing(BeadsSpy):
            def run_bd(self, args: list[str], timeout: int | None = None) -> str:
                self.calls.append(list(args))
                raise SystemExit("bd: no database")

        code, result, spy = self.verify("--read-beads", spy=Failing())
        self.assertEqual(code, 1)
        self.assertIn("the Bead could not be read", "\n".join(result["errors"]))
        self.assertEqual(spy.writes(), [])

    def test_saved_bead_read_failures_keep_their_specific_refusal(self) -> None:
        import candidate_identity as cli

        code, payload, _ = self.record("--output", str(self.output))
        self.assertEqual((code, payload["errors"]), (0, []))
        for name, raw in (("malformed", b"{"), ("utf8", b"\xff"), ("missing", None)):
            with self.subTest(source=name):
                projection = self.tmp / f"unreadable-bead-{name}.json"
                if raw is not None:
                    projection.write_bytes(raw)
                spy = BeadsSpy()
                with patch.object(cli, "check_candidate", wraps=cli.check_candidate) as check:
                    code, result, _ = self.verify("--bead-json", str(projection), spy=spy)
                    check.assert_not_called()
                    self.assertEqual(spy.calls, [])
                    self.assertEqual(code, 1)
                    self.assertEqual(set(result), {"valid", "errors"})
                    self.assertIs(result["valid"], False)
                    self.assertEqual(len(result["errors"]), 1)
                    self.assertTrue(result["errors"][0].startswith("the Bead could not be read: "))

    def test_output_unicode_failures_are_not_reported_as_input_refusals(self) -> None:
        original_open = Path.open
        failures = (
            UnicodeEncodeError("utf-8", "\ud800", 0, 1, "surrogates not allowed"),
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
        )
        for failure in failures:
            with self.subTest(error=type(failure).__name__):
                output = self.tmp / f"write-{type(failure).__name__}.json"

                @contextlib.contextmanager
                def failing_writer(path: Path, mode: str, *args: object, **kwargs: object):
                    with original_open(path, mode, *args, **kwargs) as handle:
                        with patch.object(handle, "write", side_effect=failure):
                            yield handle

                def open_with_failing_output(path: Path, mode: str = "r", *args: object, **kwargs: object):
                    if path == output and mode == "x":
                        return failing_writer(path, mode, *args, **kwargs)
                    return original_open(path, mode, *args, **kwargs)

                with patch.object(Path, "open", autospec=True, side_effect=open_with_failing_output):
                    with self.assertRaises(type(failure)) as caught:
                        self.record("--output", str(output))
                    self.assertIs(caught.exception, failure)
                self.assertEqual(output.read_bytes(), b"")


class InertCaptureTests(WorkspaceTestCase):
    """Round 2: the manifest compares raw working content with HEAD's tree, never through the index or Git."""

    def fresh(self) -> tuple[Path, str]:
        return make_workspace(Path(tempfile.mkdtemp(dir=self.tmp)))

    def manifest_entry(self, record: dict, path: str) -> dict | None:
        return next((entry for entry in record["worktree_manifest"] if entry["path"] == path), None)

    def test_index_flags_do_not_hide_a_changed_tracked_file(self) -> None:
        for flag in ("--assume-unchanged", "--skip-worktree"):
            with self.subTest(flag=flag):
                repo, base = self.fresh()
                record = self.capture(repo=repo, base_commit=base)
                git(repo, "update-index", flag, "docs/index.md")
                write(repo / "docs" / "index.md", "INDEX\n")  # same size as "index\n"
                current = self.capture(repo=repo, base_commit=base)
                self.assertEqual(self.manifest_entry(current, "docs/index.md"), {
                    "path": "docs/index.md", "change": "modified", "type": "file", "mode": "100644", "size": 6,
                    "sha256": sha(b"INDEX\n")})
                self.assertIn("docs/index.md is dirty or untracked now (modified)",
                              "\n".join(ci.verify_candidate(record, repo)))

    def test_core_filemode_false_does_not_hide_a_mode_change(self) -> None:
        record = self.capture()
        git(self.repo, "config", "core.filemode", "false")
        (self.repo / "docs" / "index.md").chmod(0o755)
        entry = self.manifest_entry(self.capture(), "docs/index.md")
        self.assertEqual((entry or {}).get("mode"), "100755")
        self.assertIn("docs/index.md is dirty or untracked now (modified)", "\n".join(ci.verify_candidate(record, self.repo)))

    def configure_filters(self, repo: Path, marker: Path) -> None:
        """Clean, smudge and process filters on every Markdown and Python file, each writing ``marker`` if run.

        The attributes are committed before the drivers exist, so committing them runs nothing. The clean filter
        also drops PAYLOAD lines, so Git would see a file with an added PAYLOAD line as unchanged.
        """
        write(repo / ".gitattributes", "*.md filter=strip\n*.py filter=proc\n")
        git(repo, "add", ".gitattributes")
        git(repo, "commit", "-q", "-m", "attributes")
        git(repo, "config", "filter.strip.clean", f"echo clean >> {marker}; sed /PAYLOAD/d")
        git(repo, "config", "filter.strip.smudge", f"echo smudge >> {marker}; cat")
        git(repo, "config", "filter.proc.process", f"echo process >> {marker}; exit 1")

    def test_configured_filters_never_run_and_cannot_hide_changed_bytes(self) -> None:
        marker = self.tmp / "filter-ran"
        self.configure_filters(self.repo, marker)
        record = self.capture()
        self.assertFalse(marker.exists(), "a configured filter ran while the candidate was recorded")
        projection = bead("proj-abc", self.baseline_lines[0], self.line(record))
        self.assertTrue(ci.check_candidate(record, root=self.repo, chain=self.chain, bead=projection)["valid"])
        self.assertFalse(marker.exists(), "a configured filter ran during a successful check")
        with (self.repo / "docs" / "index.md").open("a", encoding="utf-8") as handle:
            handle.write("PAYLOAD\n")
        git(self.repo, "add", "docs/index.md")  # the test's own add runs the clean filter, which drops PAYLOAD
        self.assertNotIn("docs/index.md", git(self.repo, "status", "--porcelain"))
        marker.unlink()
        write(self.repo / "src" / "tool.py", "print('changed')\n")
        errors = "\n".join(ci.verify_candidate(record, self.repo))
        self.assertIn("docs/index.md is dirty or untracked now (modified)", errors)
        self.assertIn("src/tool.py changed since the candidate was recorded", errors)
        self.refused_capture(scope_paths=["missing"])
        self.assertFalse(marker.exists(), "a configured filter ran during a refusal")

    def test_staging_alone_does_not_change_the_identity(self) -> None:
        record = self.capture()
        write(self.repo / "docs" / "index.md", "staged\n")
        git(self.repo, "add", "docs/index.md")
        write(self.repo / "docs" / "index.md", "index\n")  # HEAD and working tree A, index B
        current = self.capture()
        self.assertIsNone(self.manifest_entry(current, "docs/index.md"))
        self.assertEqual(independent_digest(current), independent_digest(record))
        self.assertEqual(ci.verify_candidate(record, self.repo), [])

    def test_an_index_gitlink_cannot_hide_a_directory(self) -> None:
        record = self.capture()
        write(self.repo / "src" / "plugin" / "payload.py", "PAYLOAD = 1\n")
        git(self.repo, "update-index", "--add", "--cacheinfo", f"160000,{self.base},src/plugin")
        self.assertIn("src/plugin", self.refused_capture())
        self.assertTrue(ci.verify_candidate(record, self.repo))

    def test_an_excluded_or_ignored_gitlink_is_still_refused(self) -> None:
        """Round 3: the gitlink refusal comes before exclusions and ignore rules."""
        for name, directory in (("excluded", "evidence"), ("ignored", "build")):
            with self.subTest(case=name):
                repo, base = self.fresh()
                record = self.capture(repo=repo, base_commit=base)
                write(repo / directory / "plugin" / "payload.py", "PAYLOAD = 1\n")
                git(repo, "update-index", "--add", "--cacheinfo", f"160000,{base},{directory}/plugin")
                message = self.refused_capture(repo=repo, base_commit=base)
                self.assertIn(f"{directory}/plugin is a gitlink", message)
                self.assertTrue(ci.verify_candidate(record, repo))

    def test_end_of_line_conversion_does_not_hide_changed_bytes(self) -> None:
        record = self.capture()
        git(self.repo, "config", "core.autocrlf", "true")
        (self.repo / "docs" / "index.md").write_bytes(b"index\r\n")
        git(self.repo, "add", "docs/index.md")  # stages the normalized bytes, HEAD's blob: Git now sees no change
        self.assertNotIn("docs/index.md", git(self.repo, "status", "--porcelain"))
        entry = self.manifest_entry(self.capture(), "docs/index.md")
        self.assertEqual((entry or {}).get("sha256"), sha(b"index\r\n"))
        self.assertIn("docs/index.md is dirty or untracked now (modified)", "\n".join(ci.verify_candidate(record, self.repo)))


class DeliveredSymlinkTests(WorkspaceTestCase):
    """Round 2: delivered symlinks must resolve to content the candidate binds."""

    def link(self, path: str, target: str, repo: Path | None = None) -> Path:
        link = (repo or self.repo) / path
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target)
        return link

    def test_a_payload_behind_an_unchanged_symlink_into_an_excluded_directory_is_refused(self) -> None:
        for committed in (False, True):
            with self.subTest(committed=committed):
                repo, base = make_workspace(Path(tempfile.mkdtemp(dir=self.tmp)))
                write(repo / "evidence" / "payload.py", "PAYLOAD = 1\n")
                self.link("src/active.py", "../evidence/payload.py", repo)
                if committed:
                    git(repo, "add", "src/active.py")
                    git(repo, "commit", "-q", "-m", "link")
                message = self.refused_capture(repo=repo, base_commit=base)
                self.assertIn("delivered symlink src/active.py -> ../evidence/payload.py", message)
                self.assertIn("not bound content of the candidate", message)
                write(repo / "evidence" / "payload.py", "PAYLOAD = 2\n")  # the link itself is unchanged
                self.assertIn("delivered symlink src/active.py", self.refused_capture(repo=repo, base_commit=base))

    def test_a_symlink_to_an_excluded_directory_is_refused(self) -> None:
        self.link("src/plugins", "../evidence")
        self.assertIn("delivered symlink src/plugins -> ../evidence resolves to evidence", self.refused_capture())

    def test_symlinks_into_ignored_external_git_or_absent_content_are_refused(self) -> None:
        cases = {
            "ignored file": "../build/out.bin",
            "absolute": "/etc/hostname",
            "outside the repository": "../../outside.py",
            "git metadata": "../.git/config",
            "repository root": "..",
            "absent": "missing.py",
            "through a file": "tool.py/x",
        }
        for name, target in cases.items():
            with self.subTest(case=name):
                link = self.link("src/payload", target)
                try:
                    self.assertIn("delivered symlink src/payload", self.refused_capture())
                finally:
                    link.unlink()
        self.link("src/hop", "../evidence/run.txt")
        self.link("src/chain", "hop")
        message = self.refused_capture()
        self.assertIn("delivered symlink src/chain -> hop", message)
        self.assertIn("delivered symlink src/hop -> ../evidence/run.txt", message)

    def test_symlinks_to_delivered_content_are_accepted(self) -> None:
        self.link("docs/source", "../src")
        self.link("src/chain", "link")
        self.link("docs/tool", "../src/./tool.py")
        record = self.capture()
        paths = [entry["path"] for entry in record["worktree_manifest"]]
        self.assertIn("docs/source", paths)
        self.assertEqual(ci.verify_candidate(record, self.repo), [])

class SymlinkResolutionTests(WorkspaceTestCase):
    """Round 3: resolution keeps directory-requiring components and counts every link, as the kernel does."""

    link = DeliveredSymlinkTests.link


    def test_directory_forms_of_delivered_directories_are_accepted(self) -> None:
        for target in ("../src/", "../src/.", "../src/./", ".", "./", "../src//"):
            with self.subTest(target=target):
                link = self.link("docs/source", target)
                try:
                    self.assertTrue(os.path.isdir(link))
                    record = self.capture()
                    self.assertEqual(ci.verify_candidate(record, self.repo), [])
                finally:
                    link.unlink()

    def link_chain(self, count: int) -> Path:
        """``count`` delivered links, src/l01 -> l02 -> ... -> the last -> tool.py."""
        names = [f"l{index:02d}" for index in range(1, count + 1)]
        for name, target in zip(names, names[1:] + ["tool.py"]):
            self.link(f"src/{name}", target)
        return self.repo / "src" / names[0]


    def test_forty_one_links_are_refused(self) -> None:
        first = self.link_chain(ci.MAX_LINK_HOPS + 1)
        with self.assertRaises(OSError) as caught:
            os.stat(first)
        self.assertEqual(caught.exception.errno, errno.ELOOP)
        message = self.refused_capture()
        self.assertIn("delivered symlink src/l01 -> l02 has too many levels of symlinks", message)
        self.assertNotIn("delivered symlink src/l02", message)  # 40 links from there

    def test_a_file_followed_by_a_trailing_slash_or_dot_is_refused(self) -> None:
        self.link("src/hop", "tool.py")
        for target in ("tool.py/", "tool.py/.", "tool.py/./", "tool.py//", "./tool.py/", "../src/tool.py/.", "hop/",
                       "hop/."):
            with self.subTest(target=target):
                link = self.link("src/payload", target)
                try:
                    with self.assertRaises(NotADirectoryError):
                        os.stat(link)  # the filesystem's own answer
                    message = self.refused_capture()
                    self.assertIn(f"delivered symlink src/payload -> {target} resolves through the file src/tool.py",
                                  message)
                finally:
                    link.unlink()

    def test_forty_links_are_accepted(self) -> None:
        first = self.link_chain(ci.MAX_LINK_HOPS)
        os.stat(first)  # the kernel follows 40
        record = self.capture()
        self.assertEqual(ci.verify_candidate(record, self.repo), [])


def lstat_mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


class PermissionBitsTests(WorkspaceTestCase):
    """Round 3: the full permission and special bits of delivered files and directories are bound."""

    MODE_CHANGED = "permission or special bits"

    def chmod(self, path: Path, mode: int) -> None:
        path.chmod(mode)
        self.assertEqual(lstat_mode(path), mode, f"chmod {mode:o} did not take effect on {path}")

    def assert_mode_change_refused(self, path: Path, before: int, after: int) -> None:
        self.chmod(path, before)
        record = self.capture()
        self.assertEqual(ci.verify_candidate(record, self.repo), [])
        self.chmod(path, after)
        errors = ci.verify_candidate(record, self.repo)
        self.assertIn(self.MODE_CHANGED, "\n".join(errors))
        projection = bead("proj-abc", self.baseline_lines[0], self.line(record))
        with BeadsSpy(projection).installed() as spy:
            self.assertFalse(ci.check_candidate(record, root=self.repo, chain=self.chain, bead=projection)["valid"])
        self.assertEqual(spy.writes(), [])
        current = self.capture()
        self.assertNotEqual(independent_digest(current), independent_digest(record))
        self.assertEqual(ci.verify_candidate(current, self.repo), [])
        self.chmod(path, before)
        self.assertEqual(ci.verify_candidate(record, self.repo), [])

    def test_file_permission_and_special_bit_changes_are_refused(self) -> None:
        cases = (
            ("docs/index.md", 0o644, 0o666),  # tracked, unchanged content
            ("src/new.py", 0o644, 0o666),  # added
            ("docs/index.md", 0o644, 0o640),
            ("src/tool.py", 0o755, 0o4755),
            ("src/tool.py", 0o755, 0o6755),
            ("src/tool.py", 0o755, 0o2755),
            ("src/tool.py", 0o755, 0o777),
            ("src/tool.py", 0o755, 0o1755),
            ("src/tool.py", 0o755, 0o711),
        )
        for path, before, after in cases:
            with self.subTest(path=path, before=f"{before:o}", after=f"{after:o}"):
                self.assert_mode_change_refused(self.repo / path, before, after)

    def test_directory_mode_changes_are_refused(self) -> None:
        cases = (
            ("docs", 0o755, 0o777),
            ("docs", 0o755, 0o2755),
            ("docs", 0o755, 0o1755),
            ("src", 0o755, 0o775),
            ("src", 0o755, 0o700),
            (".", 0o755, 0o775),  # the repository root
            (".", 0o755, 0o1777),
        )
        for path, before, after in cases:
            with self.subTest(path=path, before=f"{before:o}", after=f"{after:o}"):
                self.assert_mode_change_refused(self.repo / path, before, after)

    def test_modes_outside_the_delivered_content_are_not_bound(self) -> None:
        record = self.capture()
        self.chmod(self.repo / "build", 0o777)  # ignored
        self.chmod(self.repo / "build" / "out.bin", 0o666)
        self.chmod(self.repo / "evidence", 0o2777)  # excluded
        self.chmod(self.repo / "evidence" / "run.txt", 0o4755)
        self.assertEqual(ci.verify_candidate(record, self.repo), [])

    def test_the_modes_digest_uses_the_documented_serialization(self) -> None:
        record = self.capture()
        delivered = [".gitignore", "README.md", "docs", "docs/guide.md", "docs/index.md", "src", "src/link",
                     "src/new.py", "src/tool.py"]
        entries = [[".", "directory", f"{lstat_mode(self.repo):o}"]]
        for path in delivered:
            info = os.lstat(self.repo / path)
            kind = "directory" if stat.S_ISDIR(info.st_mode) else "symlink" if stat.S_ISLNK(info.st_mode) else "file"
            entries.append([path, kind, f"{stat.S_IMODE(info.st_mode):o}"])
        payload = json.dumps(entries, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        self.assertEqual(record["delivered_modes"], "sha256:" + hashlib.sha256(payload).hexdigest())

    def test_a_missing_or_malformed_modes_digest_is_refused(self) -> None:
        record = self.capture()
        missing = copy.deepcopy(record)
        del missing["delivered_modes"]
        self.assertIn("the candidate is missing delivered_modes", ci.candidate_errors(missing))
        for value in ("sha256:00", "0" * 64, None, 420):
            with self.subTest(value=value):
                self.assertIn("delivered_modes must be sha256: and 64 lowercase hex digits",
                              ci.candidate_errors({**record, "delivered_modes": value}))


class SchemaParityTests(unittest.TestCase):
    def schema(self) -> dict:
        return json.loads((ROOT / "schemas" / "candidate-identity.schema.json").read_text(encoding="utf-8"))

    def test_the_schema_matches_the_runtime_contract(self) -> None:
        schema = self.schema()
        self.assertEqual(schema["required"], list(ci.CANDIDATE_FIELDS))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["record_type"]["const"], ci.CANDIDATE_RECORD_TYPE)
        self.assertEqual(schema["properties"]["baseline"]["required"], list(ci.BASELINE_BINDING_FIELDS))
        self.assertEqual(schema["properties"]["repository"]["required"], list(ci.REPOSITORY_FIELDS))
        self.assertEqual(schema["properties"]["delivery_scope"]["required"], list(ci.SCOPE_FIELDS))
        self.assertEqual(schema["properties"]["delivery_scope"]["properties"]["live_resources"]["maxItems"], 0)
        entry = schema["properties"]["worktree_manifest"]["items"]
        self.assertEqual(entry["required"], list(ci.MANIFEST_FIELDS))
        self.assertEqual(entry["properties"]["change"]["enum"], list(ci.CHANGES))
        self.assertEqual(entry["properties"]["type"]["enum"], list(ci.FILE_TYPES))
        self.assertEqual(entry["properties"]["mode"]["enum"], [*ci.FILE_MODES, ci.SYMLINK_MODE, None])

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is not installed")
    def test_the_schema_accepts_a_recorded_candidate_and_refuses_what_the_runtime_refuses(self) -> None:
        from jsonschema import Draft202012Validator

        Draft202012Validator.check_schema(self.schema())
        validator = Draft202012Validator(self.schema())
        with tempfile.TemporaryDirectory() as directory:
            repo, base = make_workspace(Path(directory))
            record = ci.capture_candidate(repo, chain=rb.resolve_chain(fixture("baseline-v1.json")), base_commit=base,
                                          scope_paths=["docs", "src"], excluded_paths=["evidence"])
        validator.validate(record)
        refused = {
            "live resource": lambda value: value["delivery_scope"]["live_resources"].append({"resource": "svc"}),
            "parent path": lambda value: value["delivery_scope"].update(paths=["../x"]),
            "dot path": lambda value: value["delivery_scope"].update(paths=["a/./b"]),
            "deleted with digest": lambda value: value["worktree_manifest"][0].update(sha256="0" * 64),
            "result field": lambda value: value.update(status="passed"),
            "short commit": lambda value: value.update(commit="abc"),
        }
        for name, change in refused.items():
            with self.subTest(case=name):
                changed = copy.deepcopy(record)
                change(changed)
                self.assertTrue(ci.candidate_errors(changed))
                self.assertFalse(validator.is_valid(changed))

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is not installed")
    def test_the_schema_refuses_empty_terminal_components_as_the_runtime_does(self) -> None:
        from jsonschema import Draft202012Validator

        validator = Draft202012Validator(self.schema())
        with tempfile.TemporaryDirectory() as directory:
            repo, base = make_workspace(Path(directory))
            record = ci.capture_candidate(repo, chain=rb.resolve_chain(fixture("baseline-v1.json")), base_commit=base,
                                          scope_paths=["docs", "src"], excluded_paths=["evidence"])
        cases = {
            "scope with a trailing slash": lambda value: value["delivery_scope"].update(paths=["docs", "src/"]),
            "nested scope with a trailing slash": lambda value: value["delivery_scope"].update(paths=["src/x/"]),
            "exclusion with a trailing slash": lambda value: value.update(excluded_paths=["evidence/"]),
            "manifest path with a trailing slash": lambda value: value["worktree_manifest"][3].update(path="src/new.py/"),
            "bare slash": lambda value: value["delivery_scope"].update(paths=["/"]),
        }
        for name, change in cases.items():
            with self.subTest(case=name):
                changed = copy.deepcopy(record)
                change(changed)
                self.assertTrue(ci.candidate_errors(changed), name)
                self.assertFalse(validator.is_valid(changed), name)
        for path in ("src", "src/x", "a.b/c", "dir/.hidden"):
            with self.subTest(accepted=path):
                changed = copy.deepcopy(record)
                changed["delivery_scope"]["paths"] = [path]
                self.assertEqual(ci.candidate_errors(changed), [])
                self.assertTrue(validator.is_valid(changed), path)


if __name__ == "__main__":
    unittest.main()
