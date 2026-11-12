"""Artifact observation preparation: real TempGit data, fake effects, no execution grant."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import close_bead_with_summary as closure  # noqa: E402
import prepare_artifact_acceptance as preparation  # noqa: E402
from cwo_core import candidate_identity as ci  # noqa: E402
from cwo_core import requirement_baseline as rb  # noqa: E402
from tests.real_beads_fixture import configure_git_fixture

NEW = b"new-name\n"
SHA = hashlib.sha256(NEW).hexdigest()
ENV = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
ENV.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, LC_ALL="C")


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
         "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args],
        check=True, capture_output=True, text=True, env=ENV,
    )
    return result.stdout.strip()


def criterion(name: str, predicate: dict | str, kind: str = "artifact") -> dict:
    return {
        "id": name, "requirement": "Independently specified fixture obligation " + name,
        "reference": "fixture-contract/" + name,
        "expected_outcome": predicate if type(predicate) is str else preparation.PREFIX + json.dumps(predicate),
        "applicability": "required", "evidence_kind": kind,
    }


def baseline(*extra: dict) -> dict:
    return {
        "record_type": rb.BASELINE_RECORD_TYPE, "version": 1, "baseline_version": 1, "bead_id": "fixture-1",
        "criteria": [
            criterion("new-bytes", {"op": "regular-file-sha256", "path": "src/new.txt", "sha256": SHA}),
            criterion("old-absent", {"op": "path-absent", "path": "src/old.txt"}),
            *extra,
        ],
    }


def amendment(prior: dict, new: dict) -> dict:
    before = {item["id"]: item for item in prior["criteria"]}
    after = {item["id"]: item for item in new["criteria"]}
    return {
        "record_type": rb.AMENDMENT_RECORD_TYPE, "version": 1, "bead_id": prior["bead_id"],
        "amendment_id": "fixture-addition", "prior_digest": rb.record_digest(prior),
        "prior_baseline_version": prior["baseline_version"],
        "added_criterion_ids": sorted(set(after) - set(before)),
        "removed_criterion_ids": sorted(set(before) - set(after)),
        "changed_criterion_ids": sorted(key for key in set(before) & set(after) if before[key] != after[key]),
        "rationale": "Independent fixture scope revision",
        "authority": {"role": "fixture", "reference": "fixture-decision"},
        "baseline": new,
    }


@contextlib.contextmanager
def no_effects():
    targets = ("cwo_core.beads.run_bd", "cwo_core.beads.run_bd_structured",
               "close_bead_with_summary.run_bd", "close_bead_with_summary.execute")
    with contextlib.ExitStack() as stack:
        spies = [stack.enter_context(patch(target, side_effect=AssertionError("unexpected effect path")))
                 for target in targets]
        yield
        for spy in spies:
            if spy.call_count:
                raise AssertionError("preparation reached a Beads writer or production closure path")


class ArtifactPreparationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        (self.repo / "src").mkdir()
        (self.repo / "src/old.txt").write_bytes(b"old-name\n")
        (self.repo / "src/anchor.txt").write_bytes(b"anchor\n")
        (self.repo / "README").write_bytes(NEW)
        (self.repo / ".gitignore").write_text("src/ignored.txt\n", encoding="utf-8")
        git(self.repo, "init", "-q")
        configure_git_fixture(self.repo)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "fixture base")
        self.base = git(self.repo, "rev-parse", "HEAD")

    def begin(self, record: dict | None = None, *, amendments=(), incomplete=False,
              change=None, scope=("src",), excluded=()) -> None:
        self.initial = copy.deepcopy(record if record is not None else baseline())
        self.amendments = copy.deepcopy(list(amendments))
        self.chain = rb.resolve_chain(self.initial, self.amendments)
        self.baseline_path = self.tmp / "baseline.json"
        self.baseline_path.write_text(json.dumps(self.initial), encoding="utf-8")
        comments = [{"text": rb.reference_line(self.chain["bead_id"], entry["version"], entry["digest"])}
                    for entry in self.chain["baselines"]]
        self.projection = {"id": self.chain["bead_id"], "comments": comments}
        self.bead_path = self.tmp / "bead.json"
        self.bead_path.write_text(json.dumps(self.projection), encoding="utf-8")
        for index, item in enumerate(self.amendments):
            (self.tmp / f"amendment-{index}.json").write_text(json.dumps(item), encoding="utf-8")
        # Obligations and reference fixture are written before any implementation mutation.
        if not incomplete:
            (self.repo / "src/old.txt").rename(self.repo / "src/new.txt")
        (self.repo / "src/new.txt").write_bytes(NEW)
        if change is not None:
            change()
        self.candidate = ci.capture_candidate(self.repo, chain=self.chain, base_commit=self.base,
                                              scope_paths=scope, excluded_paths=excluded)
        comments.append({"text": ci.candidate_reference_line(self.chain["bead_id"], ci.candidate_digest(self.candidate))})
        self.candidate_path = self.tmp / "candidate.json"
        self.candidate_path.write_text(json.dumps(self.candidate), encoding="utf-8")
        self.bead_path.write_text(json.dumps(self.projection), encoding="utf-8")

    def assess(self, *, initial=None, candidate=None, bead=None, amendments=None) -> dict:
        with no_effects():
            result = preparation.prepare(
                self.repo, self.initial if initial is None else initial,
                self.candidate if candidate is None else candidate,
                self.projection if bead is None else bead,
                self.amendments if amendments is None else amendments,
            )
        for key in ("qualified", "effect_authority", "successful_closure_available", "production_accepted",
                    "bead_projection_authenticated"):
            self.assertIs(result[key], False)
        self.assertIn("production-closure", result["remaining_open"])
        return result

    def statuses(self, result: dict) -> dict:
        return {entry["id"]: entry["status"] for entry in result["criteria"]}

    def test_real_rename_has_complete_but_non_authoritative_bound_observations(self) -> None:
        self.begin()
        for committed in (False, True):
            with self.subTest(committed=committed):
                if committed:
                    git(self.repo, "add", "-A")
                    git(self.repo, "commit", "-q", "-m", "EXAMPLE completed rename")
                    self.candidate = ci.capture_candidate(self.repo, chain=self.chain, base_commit=self.base,
                                                          scope_paths=("src",))
                    self.projection["comments"].append({"text": ci.candidate_reference_line(
                        self.chain["bead_id"], ci.candidate_digest(self.candidate))})
                    self.assertEqual(self.candidate["worktree_manifest"], [])
                result = self.assess()
                self.assertTrue(result["artifact_observations_complete"], result)
                self.assertEqual(self.statuses(result), {"new-bytes": "PASSED", "old-absent": "PASSED"})
                self.assertEqual(result["required_criterion_ids"], ["new-bytes", "old-absent"])
                self.assertEqual(result["bindings"]["resolved_baseline"], self.chain)
                self.assertEqual(result["bindings"]["candidate"], self.candidate)
                self.assertEqual(result["candidate_checks"], {"before": [], "after": []})
                body = {key: value for key, value in result.items() if key != "report_digest"}
                data = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                self.assertEqual(result["report_digest"], "sha256:" + hashlib.sha256(data).hexdigest())

    def test_each_artifact_is_read_once_even_with_multiple_recorded_criteria(self) -> None:
        self.begin(baseline(criterion("also-new", {"op": "regular-file-sha256", "path": "src/new.txt", "sha256": SHA})))
        with patch.object(preparation, "_read_regular", wraps=preparation._read_regular) as reader:
            self.assertTrue(self.assess()["artifact_observations_complete"])
        self.assertEqual(reader.call_count, 1)

    def test_incomplete_rename_cannot_pass_with_unrelated_passing_bytes(self) -> None:
        self.begin(incomplete=True)
        result = self.assess()
        self.assertFalse(result["artifact_observations_complete"])
        self.assertEqual(self.statuses(result), {"new-bytes": "PASSED", "old-absent": "FAILED"})

    def test_missing_expected_file_is_failed_and_every_named_requirement_is_accounted(self) -> None:
        extra = criterion("named-required", {"op": "regular-file-sha256", "path": "src/missing.txt", "sha256": SHA})
        self.begin(baseline(extra))
        result = self.assess()
        self.assertFalse(result["artifact_observations_complete"])
        self.assertEqual(self.statuses(result)["named-required"], "FAILED")
        self.assertEqual(result["required_criterion_ids"], ["new-bytes", "old-absent", "named-required"])
        changed = copy.deepcopy(self.initial)
        changed["criteria"].pop()
        self.assertFalse(self.assess(initial=changed)["artifact_observations_complete"])

    def test_bytes_untracked_modes_and_tree_drift_invalidate_the_real_candidate(self) -> None:
        self.begin()
        path = self.repo / "src/new.txt"
        mode = path.stat().st_mode & 0o7777
        mutations = (
            (lambda: path.write_bytes(b"NEW-NAME\n"), lambda: path.write_bytes(NEW)),
            (lambda: (self.repo / "src/extra").write_bytes(b"x"), lambda: (self.repo / "src/extra").unlink()),
            (lambda: path.chmod(mode ^ 0o020), lambda: path.chmod(mode)),
        )
        for mutate, restore in mutations:
            with self.subTest(mutation=mutate):
                mutate()
                result = self.assess()
                self.assertFalse(result["artifact_observations_complete"])
                self.assertTrue(result["candidate_checks"]["before"])
                restore()
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "fixture changed tree")
        self.assertTrue(self.assess()["candidate_checks"]["before"])

    def test_post_observation_edit_is_detected_by_real_reverification(self) -> None:
        self.begin()
        observe = preparation._artifact

        def drift(*args):
            result = observe(*args)
            if args[1] == "src/new.txt":
                (self.repo / "src/new.txt").write_bytes(b"drifted\n")
            return result

        with patch.object(preparation, "_artifact", side_effect=drift):
            result = self.assess()
        self.assertFalse(result["artifact_observations_complete"])
        self.assertTrue(result["candidate_checks"]["after"])

    def test_additive_amendment_is_consumed_but_stale_or_weakening_chain_is_refused(self) -> None:
        prior = baseline()
        new = baseline(criterion("added", {"op": "regular-file-sha256", "path": "src/anchor.txt",
                                          "sha256": hashlib.sha256(b"anchor\n").hexdigest()}))
        new["baseline_version"] = 2
        addition = amendment(prior, new)
        self.begin(prior, amendments=[addition])
        self.assertTrue(self.assess()["artifact_observations_complete"])
        stale = copy.deepcopy(self.candidate)
        stale["baseline"] = {"version": 1, "digest": rb.record_digest(prior)}
        self.assertFalse(self.assess(candidate=stale)["artifact_observations_complete"])
        changed = copy.deepcopy(new)
        changed["baseline_version"] = 3
        changed["criteria"].pop(1)
        result = self.assess(amendments=[addition, amendment(new, changed)])
        self.assertFalse(result["artifact_observations_complete"])
        self.assertIn("only amendments that add criteria", " ".join(result["errors"]))

    def test_prose_review_and_recreating_service_obligations_stay_unassessable(self) -> None:
        obligations = (
            criterion("prose", "All names have been reviewed."),
            criterion("review", "Final review has no blockers.", "review-gate"),
            criterion("service", "Retired service is stopped and its active recreating service is disabled.", "validator"),
            criterion("service-json", {"op": "service-inactive", "path": "src/new.txt"}),
        )
        self.begin(baseline(*obligations))
        result = self.assess()
        self.assertFalse(result["artifact_observations_complete"])
        for item in obligations:
            self.assertEqual(self.statuses(result)[item["id"]], "UNASSESSABLE")
        self.assertEqual(self.statuses(result)["new-bytes"], "PASSED")

    def test_source_prose_baseline_remains_valid_and_unassessable(self) -> None:
        source = json.loads((ROOT / "tests/fixtures/requirement-baseline/baseline-v1.json").read_text(encoding="utf-8"))
        self.assertEqual(rb.baseline_errors(source), [])
        self.begin(source)
        result = self.assess()
        self.assertFalse(result["artifact_observations_complete"])
        self.assertEqual(result["required_criterion_ids"], rb.required_criterion_ids(source))
        for entry in result["criteria"]:
            if entry["id"] in result["required_criterion_ids"]:
                self.assertEqual(entry["status"], "UNASSESSABLE")

    def test_outside_scope_excluded_ignored_and_unbound_absence_cannot_pass(self) -> None:
        extra = [
            criterion("outside", {"op": "regular-file-sha256", "path": "README", "sha256": SHA}),
            criterion("excluded", {"op": "regular-file-sha256", "path": "src/evidence/out", "sha256": SHA}),
            criterion("ignored", {"op": "regular-file-sha256", "path": "src/ignored.txt", "sha256": SHA}),
            criterion("unbound-absence", {"op": "path-absent", "path": "src/never-bound"}),
            criterion("escape", {"op": "path-absent", "path": "../outside"}),
        ]

        def files():
            (self.repo / "src/evidence").mkdir()
            (self.repo / "src/evidence/out").write_bytes(NEW)
            (self.repo / "src/ignored.txt").write_bytes(NEW)

        self.begin(baseline(*extra), change=files, excluded=("src/evidence",))
        result = self.assess()
        self.assertFalse(result["artifact_observations_complete"])
        for item in extra:
            self.assertEqual(self.statuses(result)[item["id"]], "UNASSESSABLE")

    def test_oversize_and_unreadable_regular_files_stay_unassessable(self) -> None:
        self.begin()
        with patch.object(preparation, "MAX_ARTIFACT", 1):
            result = self.assess()
        self.assertEqual(self.statuses(result)["new-bytes"], "UNASSESSABLE")
        with patch.object(preparation, "_read_regular", side_effect=PermissionError("unreadable")):
            result = self.assess()
        self.assertEqual(self.statuses(result)["new-bytes"], "UNASSESSABLE")
        self.assertFalse(result["artifact_observations_complete"])

    def test_observer_rejects_special_files_and_symlink_ancestors(self) -> None:
        os.mkfifo(self.repo / "src/fifo")
        (self.repo / "alias").symlink_to("src", target_is_directory=True)
        fd = preparation._directory(self.repo)
        self.addCleanup(os.close, fd)
        for path in ("src/fifo", "alias/old.txt"):
            with self.subTest(path=path), self.assertRaises(preparation.PreparationError):
                preparation._artifact(fd, path, 100, True)

    def cli(self) -> tuple[int, dict]:
        stdout = io.StringIO()
        with no_effects(), contextlib.redirect_stdout(stdout):
            code = preparation.main(["--root", str(self.repo), "--baseline", str(self.baseline_path),
                                     "--candidate", str(self.candidate_path), "--bead-json", str(self.bead_path)])
        return code, json.loads(stdout.getvalue())

    def test_cli_parse_failures_are_structured_and_never_complete(self) -> None:
        self.begin()
        bad = (
            b'{"x":1,"x":2}', b"\xff", b'{"x":NaN}', b'{"x":1e99}', b'{"x":9223372036854775808}',
            b'{"x":' + b"[" * 40 + b"0" + b"]" * 40 + b"}",
            b'{"x":"\\ud800"}', b"[]", b"{", b"x" * (preparation.MAX_DOCUMENT + 1),
        )
        for data in bad:
            with self.subTest(data=data[:60]):
                self.baseline_path.write_bytes(data)
                code, result = self.cli()
                self.assertEqual(code, 1)
                self.assertFalse(result["artifact_observations_complete"])
                self.assertTrue(result["errors"])

    def test_cli_diagnostic_never_enters_production_and_existing_closure_still_refuses_success(self) -> None:
        self.begin()
        code, result = self.cli()
        self.assertEqual(code, 0)
        self.assertTrue(result["artifact_observations_complete"])
        execute = closure.execute
        for disposition in ("completed", "validated"):
            args = closure.parser().parse_args(["--bead", "fixture-1", "--disposition", disposition,
                                                "--why", "Delivered", "--close"])
            with no_effects(), self.assertRaisesRegex(ValueError, "successful closure is unavailable"):
                execute(args)
        args = closure.parser().parse_args([
            "--bead", "fixture-1", "--disposition", "pending-acceptance", "--why", "Review remains open",
            "--dry-run", "--meaningful", "--who", "author", "--what", "Rename", "--how", "Offline artifact observation",
            "--when", "fixture time", "--where", "disposable repository", "--evidence", "diagnostic report",
            "--residual-risk", "Review and custody remain open", "--follow-up", "Independent review",
        ])
        with no_effects():
            pending = execute(args)
        self.assertEqual(pending["closure_memory_quality"], "complete")
        self.assertFalse(pending["closed"])
        self.assertFalse(pending["comment_posted"])


    def test_order_missing_and_superseding_projection_references_refuse(self) -> None:
        self.begin()
        for comments in (list(reversed(self.projection["comments"])), self.projection["comments"][:1],
                         self.projection["comments"] + [{"text": ci.candidate_reference_line(
                             self.chain["bead_id"], "sha256:" + "f" * 64)}]):
            with self.subTest(comments=comments):
                result = self.assess(bead={"id": self.chain["bead_id"], "comments": comments})
                self.assertFalse(result["artifact_observations_complete"])
                self.assertTrue(result["candidate_checks"]["before"])

    def test_symlink_artifacts_are_rejected_without_following(self) -> None:
        def link():
            (self.repo / "src/new.txt").unlink()
            (self.repo / "src/new.txt").symlink_to("anchor.txt")

        self.begin(change=link)
        result = self.assess()
        self.assertFalse(result["artifact_observations_complete"])
        self.assertEqual(self.statuses(result)["new-bytes"], "UNASSESSABLE")


if __name__ == "__main__":
    unittest.main()
