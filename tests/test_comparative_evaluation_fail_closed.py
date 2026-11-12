"""Negative regressions for the three-arm comparative evaluation's study-validity controls.

Each test names one way a changed scorer or protocol, or a missing, substituted,
unscheduled or malformed run, could have counted as evidence, and shows that it
now fails closed. Nothing here runs a model or opens a network connection.
Hidden probes run as local subprocesses against inert workspaces built in
temporary directories.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import comparative_evaluation as cli  # noqa: E402
from cwo_core import comparative_evaluation as ce  # noqa: E402
from cwo_core.frozen_protocol import file_sha256  # noqa: E402

from tests.test_comparative_evaluation import load_protocol, load_hidden, reseal, arm, files_of  # noqa: E402

STUDY = ROOT / "evaluation" / "three-arm"
MARKER = "cwo-probe-complete:"
SCORER = "scripts/cwo_core/comparative_evaluation.py"
LOCK_PATHS = {
    "governing-prompt": "prompts/cwo-sol-operator-e.md",
    "controller": "scripts/comparative_evaluation.py",
    "manifest": "evaluation/three-arm/protocol.json",
    "scorer": SCORER,
    "scorer-dependency": "scripts/cwo_core/frozen_protocol.py",
    "hidden-checks": "evaluation/three-arm/hidden/checks.json",
    "build-freeze": "evaluation/three-arm/build-freeze.json",
}
# The build freeze the rehearsal records were observed under; the shipped one is empty.
FIXTURE_BUILD_FREEZE = {
    "schema_version": "cwo-comparative-evaluation-build-freeze:v1",
    "codex_harness": {
        "form": "container-image",
        "reference": "rehearsal fixture codex image",
        "sha256": hashlib.sha256(b"cwo rehearsal fixture: codex harness").hexdigest(),
    },
    "observer_harness": {
        "form": "executable",
        "reference": "rehearsal fixture observer",
        "sha256": hashlib.sha256(b"cwo rehearsal fixture: observer harness").hexdigest(),
    },
}








def live_digests(root: Path = ROOT) -> dict[str, str]:
    return {path: file_sha256(root / path) for path in LOCK_PATHS.values()}


def current_lock(root: Path = ROOT) -> dict:
    protocol = json.loads((root / LOCK_PATHS["manifest"]).read_text(encoding="utf-8"))
    return ce.build_frozen_protocol_lock(protocol, live_digests(root))


def stamped_runs(lock: dict | None = None) -> list:
    lock = lock or current_lock()
    runs = json.loads((STUDY / "rehearsal" / "runs.json").read_text(encoding="utf-8"))
    for run in runs:
        run["study_lock_sha256"] = lock["lock_sha256"]
    return runs


def record(run_id: str) -> dict:
    return copy.deepcopy(next(run for run in stamped_runs() if run["run_id"] == run_id))


def score(runs: list, protocol: dict | None = None, build_freeze: dict | None = None) -> dict:
    return ce._score_runs(
        protocol or load_protocol(),
        load_hidden(),
        runs,
        study_lock_sha256=current_lock()["lock_sha256"],
        build_freeze=build_freeze or FIXTURE_BUILD_FREEZE,
    )


def scored_row(result: dict, run_id: str) -> dict:
    return next(row for row in result["runs"] if row["run_id"] == run_id)


def run_cli(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(argv)
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()






def observe(task_id: str, overlay: dict[str, str | None]) -> dict[str, str]:
    """Build a workspace from the seed and overlay, observe it, and evaluate every hidden check.

    The observer records the changed paths and final files, and runs each probe
    with a fresh nonce as its only standard input line, recording the exit
    status and whether the completion marker for that nonce appeared. It never
    trusts the exit status alone. Checks over transcripts, outbound records and
    observer events are not exercised here and stay unobserved.
    """

    seed = STUDY / "tasks" / task_id / "seed"
    checks = load_hidden()["tasks"][task_id]
    probes = {}
    with tempfile.TemporaryDirectory() as temp:
        workspace = Path(temp) / "workspace"
        shutil.copytree(seed, workspace, ignore=shutil.ignore_patterns("__pycache__"))
        for relative, text in overlay.items():
            target = workspace / relative
            if text is None:
                target.unlink()
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8")
        before, after = files_of(seed), files_of(workspace)
        for check in checks:
            if check["kind"] != "probe":
                continue
            nonce = secrets.token_hex(16)
            completed = subprocess.run(
                [sys.executable, "-I", "-B", str(STUDY / "hidden" / check["probe"]), str(workspace)],
                input=nonce + "\n",
                capture_output=True,
                text=True,
                timeout=60,
                cwd=temp,
            )
            probes[check["id"]] = {
                "exit": completed.returncode,
                "completed": f"{MARKER}{nonce}" in completed.stdout.splitlines(),
            }
    changed_paths = sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))
    run = {
        "transcript": None,
        "observation": {"changed_paths": changed_paths, "final_files": after, "outbound": None, "events": None, "probes": probes},
    }
    return {check["id"]: ce.evaluate_check(check, run) for check in checks}


def probe_results(task_id: str, overlay: dict[str, str | None]) -> dict[str, str]:
    probe_ids = {check["id"] for check in load_hidden()["tasks"][task_id] if check["kind"] == "probe"}
    return {check_id: result for check_id, result in observe(task_id, overlay).items() if check_id in probe_ids}


def reference(task_id: str) -> dict[str, str]:
    return files_of(STUDY / "hidden" / "reference" / task_id)


class StudyLockTests(unittest.TestCase):
    """Scoring verifies the original study lock and refuses on any scoring-artifact drift."""

    def test_scoring_without_a_study_lock_is_refused(self) -> None:
        code, out, _ = run_cli(["score", str(STUDY / "rehearsal" / "runs.json")])
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")

    def test_a_lock_whose_scoring_artifacts_differ_from_the_live_files_is_refused(self) -> None:
        protocol = load_protocol()
        self.assertEqual(ce.study_lock_errors(current_lock(), ROOT), [])
        for label, path in LOCK_PATHS.items():
            with self.subTest(label=label):
                lock = ce.build_frozen_protocol_lock(protocol, {**live_digests(), path: "0" * 64})
                errors = ce.study_lock_errors(lock, ROOT)
                self.assertTrue(any(f"study lock binding {label} " in error for error in errors), errors)

    def test_a_lock_with_a_broken_seal_or_for_another_protocol_is_refused(self) -> None:
        protocol = load_protocol()
        broken = {**current_lock(), "lock_sha256": "1" * 64}
        self.assertTrue(any("lock_sha256" in e for e in ce.study_lock_errors(broken, ROOT)))
        other = copy.deepcopy(protocol)
        other["analysis"]["limits"].append("a limit added after the lock")
        lock = ce.build_frozen_protocol_lock(reseal(other), live_digests())
        errors = ce.study_lock_errors(lock, ROOT)
        self.assertTrue(any("run contract" in error for error in errors), errors)
        self.assertNotEqual(ce.study_lock_errors({"schema_version": "x"}, ROOT), [])

    def test_the_cli_refuses_to_score_once_the_scorer_changes_after_the_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp) / "repo"
            for relative in ("scripts/comparative_evaluation.py", "prompts/cwo-sol-operator-e.md"):
                (repo / relative).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, repo / relative)
            shutil.copytree(ROOT / "scripts" / "cwo_core", repo / "scripts" / "cwo_core", ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copytree(STUDY, repo / "evaluation" / "three-arm", ignore=shutil.ignore_patterns("__pycache__"))
            lock = current_lock(repo)
            lock_path, runs_path = Path(temp) / "lock.json", Path(temp) / "runs.json"
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            runs_path.write_text(json.dumps(stamped_runs(lock)), encoding="utf-8")
            argv = ["--root", str(repo / "evaluation" / "three-arm"), "score", str(runs_path), "--lock", str(lock_path)]
            code, out, _ = run_cli(argv)
            self.assertEqual(code, 0, out)
            self.assertEqual(json.loads(out)["study_lock_sha256"], lock["lock_sha256"])
            with (repo / SCORER).open("a", encoding="utf-8") as handle:
                handle.write("\n# a scoring change made after outcomes were seen\n")
            code, out, _ = run_cli(argv)
            self.assertEqual(code, 1)
            report = json.loads(out)
            self.assertNotIn("runs", report)
            self.assertTrue(any("study lock binding scorer " in error for error in report["errors"]), report)

    def test_the_scoring_entry_point_scores_nothing_under_a_stale_lock(self) -> None:
        protocol = load_protocol()
        stale = ce.build_frozen_protocol_lock(protocol, {**live_digests(), SCORER: "0" * 64})
        result = ce.score_under_study_lock(stamped_runs(stale), stale, ROOT)
        self.assertEqual(set(result), {"valid", "errors"})
        self.assertTrue(any("study lock binding scorer " in error for error in result["errors"]), result)
        lock = current_lock()
        shipped = json.loads((STUDY / "build-freeze.json").read_text(encoding="utf-8"))
        self.assertEqual(ce.score_under_study_lock(stamped_runs(lock), lock, ROOT), score(stamped_runs(lock), build_freeze=shipped))

    def test_records_bound_to_another_lock_are_not_included(self) -> None:
        run = record("r17-overhead-slugify-baseline")
        self.assertEqual(scored_row(score([run]), run["run_id"])["comparison"], "included")
        run["study_lock_sha256"] = "f" * 64
        result = score([run])
        self.assertEqual(scored_row(result, run["run_id"])["comparison"], "excluded-protocol-mismatch")
        self.assertEqual(result["study_lock_sha256"], current_lock()["lock_sha256"])


class AmendmentEnforcementTests(unittest.TestCase):
    """The operational validator enforces the amendment rules, not only a helper."""

    def amended(self) -> tuple[dict, dict]:
        previous = load_protocol()
        proposed = copy.deepcopy(previous)
        proposed["scoring"]["interventions"] = "any message or action from a person during a run"
        proposed["version"] = 2
        proposed["preregistration"]["amendments"].append(
            {
                "version": 2,
                "prior_digest": ce.preregistration_digest(previous),
                "rationale": "clarify the intervention definition before any run",
                "scope_authority": "operator decision recorded with the amendment",
                "changed_sections": ["scoring"],
                "recorded_before_outcomes": True,
            }
        )
        return previous, reseal(proposed)

    def validate_with_history(self, proposed: dict, history: list[dict]) -> list[str]:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "three-arm"
            shutil.copytree(STUDY, root, ignore=shutil.ignore_patterns("__pycache__"))
            (root / "history").mkdir()
            for version, document in enumerate(history, start=1):
                (root / "history" / f"v{version}.json").write_text(json.dumps(document), encoding="utf-8")
            (root / "protocol.json").write_text(json.dumps(proposed), encoding="utf-8")
            return ce.validate_protocol(proposed, load_hidden(), root=root)

    def test_an_amended_protocol_without_its_history_is_refused(self) -> None:
        _, proposed = self.amended()
        errors = ce.validate_protocol(proposed, load_hidden())
        self.assertTrue(any("prior version" in error for error in errors), errors)

    def test_a_valid_amendment_with_its_history_validates(self) -> None:
        previous, proposed = self.amended()
        self.assertEqual(self.validate_with_history(proposed, [previous]), [])

    def test_each_broken_amendment_record_is_refused_by_the_validator(self) -> None:
        previous, _ = self.amended()
        cases = {
            "empty rationale": (("rationale", ""), "rationale must be a non-empty string"),
            "empty authority": (("scope_authority", " "), "scope_authority must be a non-empty string"),
            "wrong prior digest": (("prior_digest", "0" * 64), "prior_digest"),
            "wrong sections": (("changed_sections", ["analysis"]), "changed_sections"),
            "no sections": (("changed_sections", []), "changed_sections"),
            "unknown section": (("changed_sections", ["scoring", "everything"]), "changed_sections"),
            "timing not a boolean": (("recorded_before_outcomes", "yes"), "recorded_before_outcomes"),
            "scoring after outcomes": (("recorded_before_outcomes", False), "cannot be amended after outcomes"),
        }
        for name, ((field, value), expected) in cases.items():
            with self.subTest(name=name):
                _, proposed = self.amended()
                proposed["preregistration"]["amendments"][-1][field] = value
                errors = self.validate_with_history(reseal(proposed), [previous])
                self.assertTrue(any(expected in error for error in errors), errors)

    def test_history_that_does_not_hash_to_the_prior_digest_is_refused(self) -> None:
        previous, proposed = self.amended()
        tampered = copy.deepcopy(previous)
        tampered["purpose"] += " Rewritten later."
        errors = self.validate_with_history(proposed, [reseal(tampered)])
        self.assertTrue(any("prior_digest" in error for error in errors), errors)

    def test_scoring_refuses_an_amendment_that_claims_to_precede_recorded_outcomes(self) -> None:
        previous, proposed = self.amended()
        run = record("r17-overhead-slugify-baseline")
        run["protocol_digest"] = previous["preregistration"]["digest"]
        result = score([run], protocol=proposed)
        self.assertIn("errors", result)
        self.assertTrue(any("recorded before outcomes" in error for error in result["errors"]), result)


class IdentitySubstitutionTests(unittest.TestCase):
    """Every frozen arm setting is part of the observed identity and is compared."""

    def test_the_expected_identity_binds_every_frozen_arm_setting(self) -> None:
        full = arm(load_protocol(), "cwo-full")
        identity = ce.expected_identity(full)
        for key in ("lead", "workers", "reviewers", "instructions", "tools", "permissions", "budget"):
            self.assertIn(key, identity)
        self.assertEqual(identity["instructions"], full["instructions"])
        self.assertEqual(identity["tools"], full["tools"])
        self.assertEqual(identity["permissions"], full["permissions"])
        for reviewer in identity["reviewers"]:
            self.assertEqual(set(reviewer), {"executor", "provider", "harness", "model", "reasoning_effort", "service_tier"})

    def test_each_substitution_excludes_the_run(self) -> None:
        def reviewer(field, value):
            return lambda identity: identity["reviewers"][0].update({field: value})

        cases = {
            "reviewer model": reviewer("model", "claude-opus-4-1"),
            "reviewer provider": reviewer("provider", "anthropic_api"),
            "reviewer harness": reviewer("harness", "claude-desktop"),
            "reviewer effort": reviewer("reasoning_effort", "low"),
            "reviewer removed": lambda identity: identity["reviewers"].pop(),
            "reviewer added": lambda identity: identity["reviewers"].append({**identity["reviewers"][0], "executor": "extra_critic"}),
            "instructions file": lambda identity: identity["instructions"].update(model_instructions_file="prompts/other.md"),
            "system instructions": lambda identity: identity["instructions"].update(system="custom system prompt"),
            "task messages": lambda identity: identity.update(task_message_sha256=["0" * 64]),
            "tools": lambda identity: identity["tools"].update(network="available"),
            "permissions": lambda identity: identity["permissions"].update(sandbox_mode="danger-full-access"),
            "worker effort": lambda identity: identity["workers"][0].update(reasoning_effort="low"),
            "instruction prompt": lambda identity: identity.update(instruction_profile_sha256="1" * 64),
        }
        base = record("r03-trap-retry-full")
        self.assertEqual(scored_row(score([base]), base["run_id"])["comparison"], "included")
        for name, mutate in cases.items():
            with self.subTest(name=name):
                run = copy.deepcopy(base)
                mutate(run["observed_identity"])
                self.assertEqual(scored_row(score([run]), run["run_id"])["comparison"], "excluded-identity-drift")

    def test_an_observed_codex_reviewer_outside_the_rule_is_excluded(self) -> None:
        for field, value in (("model", "gpt-5.6-sol"), ("reasoning_effort", "ultra"), ("service_tier", "flex")):
            with self.subTest(field=field):
                run = record("r03-trap-retry-full")
                run["observed_identity"]["reviewers"][0].update(
                    {"provider": "internal_codex", "harness": "codex_cli", "model": "example-codex-model",
                     "reasoning_effort": "high", "service_tier": "default", field: value}
                )
                self.assertEqual(scored_row(score([run]), run["run_id"])["comparison"], "excluded-operator-rule")

    def test_task_message_digests_are_bound_to_the_brief_files(self) -> None:
        protocol = load_protocol()
        protocol["tasks"][0]["brief_sha256"] = ["0" * 64]
        errors = ce.validate_protocol(reseal(protocol), load_hidden(), root=STUDY)
        self.assertIn("tasks[0].brief_sha256 does not match the brief files", errors)

    def test_an_unobserved_harness_build_is_not_comparable(self) -> None:
        run = record("r03-trap-retry-full")
        run["observed_identity"]["harness_build"] = None
        self.assertEqual(scored_row(score([run]), run["run_id"])["comparison"], "excluded-identity-unobserved")

    def test_runs_on_different_harness_builds_are_not_paired(self) -> None:
        control, treated = record("r01-trap-retry-baseline"), record("r02-trap-retry-no-outside")
        pairs = score([control, treated])["estimands"]["package-change"]["governance-traps"]
        self.assertEqual((pairs["complete_pairs"], pairs["build_mismatch_pairs"]), (1, 0))
        treated["observed_identity"]["harness_build"] = hashlib.sha256(b"another build").hexdigest()
        result = score([control, treated])
        self.assertEqual(scored_row(result, treated["run_id"])["comparison"], "excluded-build-mismatch")
        self.assertEqual(result["estimands"]["package-change"]["governance-traps"]["complete_pairs"], 0)
        rows = [scored_row(score([control, record("r02-trap-retry-no-outside")]), run_id) for run_id in (treated["run_id"], control["run_id"])]
        rows[0] = {**rows[0], "harness_build": treated["observed_identity"]["harness_build"]}
        pairs = ce._pair_estimate([(rows[0], rows[1])])
        self.assertEqual((pairs["complete_pairs"], pairs["build_mismatch_pairs"]), (0, 1))


EARLY_EXITS = {
    "SystemExit(0) at import": "raise SystemExit(0)\n",
    "sys.exit() at import": "import sys\nsys.exit()\n",
    "os._exit(0) at import": "import os\nos._exit(0)\n",
}
# The workspace module each probe imports first.
FIRST_IMPORT = {
    "overhead-slugify": "textutil/slug.py",
    "overhead-cli-flag": "tool/cli.py",
    "trap-duplicate-job-retry": "jobs/client.py",
    "trap-migration-rollback": "db/migrate.py",
    "trap-hidden-dependency": "core/calendar.py",
    "trap-credential-handling": "deploy/deploy.py",
    "trap-continuation-after-compaction": "api/v1/handlers.py",
    "trap-seeded-hostile-return": "calc/ops.py",
}


class ProbeCompletionTests(unittest.TestCase):
    """A probe passes only by reaching its completion marker; any early exit fails."""

    def test_every_probe_task_is_covered(self) -> None:
        hidden = load_hidden()
        with_probes = {task for task, checks in hidden["tasks"].items() if any(c["kind"] == "probe" for c in checks)}
        self.assertEqual(with_probes, set(FIRST_IMPORT))

    def test_an_early_exit_in_candidate_code_fails_every_probe(self) -> None:
        for task_id, module in FIRST_IMPORT.items():
            solution = reference(task_id)
            original = solution.get(module, (STUDY / "tasks" / task_id / "seed" / module).read_text(encoding="utf-8"))
            for name, prefix in EARLY_EXITS.items():
                with self.subTest(task=task_id, exit=name):
                    results = probe_results(task_id, {**solution, module: prefix + original})
                    self.assertTrue(results)
                    self.assertEqual(set(results.values()), {"fail"}, results)

    def test_the_reference_reaches_the_marker_and_a_wrong_nonce_does_not_count(self) -> None:
        self.assertEqual(set(probe_results("trap-hidden-dependency", reference("trap-hidden-dependency")).values()), {"pass"})
        self.assertEqual(ce.probe_observation(0, f"noise\n{MARKER}n1\n", "n1"), {"exit": 0, "completed": True})
        self.assertEqual(ce.probe_observation(0, f"{MARKER}n1\n", "n2"), {"exit": 0, "completed": False})
        self.assertEqual(ce.probe_observation(0, f"{MARKER}\n", ""), {"exit": 0, "completed": False})
        self.assertEqual(ce.probe_observation(0, f"x{MARKER}n1\n", "n1"), {"exit": 0, "completed": False})
        self.assertEqual(ce.probe_observation(-9, "", "n1"), {"exit": -9, "completed": False})

    def test_exit_zero_without_the_marker_fails(self) -> None:
        check = {"id": "p", "kind": "probe", "probe": "probes/x.py"}
        self.assertEqual(ce.evaluate_check(check, {"observation": {"probes": {"p": {"exit": 0, "completed": False}}}}), "fail")
        self.assertEqual(ce.evaluate_check(check, {"observation": {"probes": {"p": {"exit": 0, "completed": True}}}}), "pass")
        self.assertEqual(ce.evaluate_check(check, {"observation": {"probes": {}}}), "unobserved")

    def test_signal_termination_is_an_observed_failure(self) -> None:
        check = {"id": "p", "kind": "probe", "probe": "probes/x.py"}
        for code in (-9, -15, 137):
            with self.subTest(code=code):
                run = {"observation": {"probes": {"p": {"exit": code, "completed": False}}}}
                self.assertEqual(ce.evaluate_check(check, run), "fail")
        run = record("r17-overhead-slugify-baseline")
        run["observation"]["probes"]["empty-slug"] = {"exit": -9, "completed": False}
        scored = scored_row(score([run]), run["run_id"])
        self.assertEqual((scored["checks"]["empty-slug"], scored["hidden_checks"]), ("fail", "fail"))
        self.assertIs(scored["false_completion_claim"], True)

    def test_malformed_probe_records_are_refused(self) -> None:
        for value in ({"exit": True, "completed": False}, {"exit": 0}, {"exit": "0", "completed": True},
                      {"exit": 0, "completed": "yes"}, {"exit": 0.0, "completed": True}, [0]):
            with self.subTest(value=value):
                run = record("r17-overhead-slugify-baseline")
                run["observation"]["probes"]["empty-slug"] = value
                errors = ce._validate_run(run, "runs[0]", load_protocol())
                self.assertTrue(any("observation.probes.empty-slug" in error for error in errors), errors)


class ScheduledCountingTests(unittest.TestCase):
    """Only scheduled runs count; every scheduled run is listed with its disposition."""

    def test_an_unscheduled_record_enters_no_scheduled_denominator(self) -> None:
        runs = stamped_runs()
        before = score(runs)
        extra = copy.deepcopy(next(run for run in runs if run["run_id"] == "r11-trap-hostile-no-outside"))
        extra.update(run_id="r99-extra-replicate", replicate=4, schedule_position=82)
        after = score([*runs, extra])
        self.assertNotIn("errors", after)
        self.assertEqual(after["summary"], before["summary"])
        self.assertEqual(after["estimands"], before["estimands"])
        self.assertEqual(after["runs"], before["runs"])
        self.assertEqual([row["run_id"] for row in after["unscheduled_records"]], ["r99-extra-replicate"])
        for stratum in ce.STRATA:
            for arm_id in ce.ARM_IDS:
                summary = after["summary"][stratum][arm_id]
                self.assertEqual(sum(summary["dispositions"].values()), summary["scheduled"])
        no_outside = after["summary"]["governance-traps"]["cwo-no-outside-review"]
        self.assertEqual(no_outside["success_without_failed_infrastructure"], "2/17")

    def test_every_missing_scheduled_run_is_listed_individually(self) -> None:
        result = score(stamped_runs())
        schedule = ce.build_schedule(load_protocol())
        self.assertEqual([row["schedule_position"] for row in result["runs"]], [row["position"] for row in schedule])
        missing = [row for row in result["runs"] if row["disposition"] == "missing-record"]
        self.assertEqual(len(missing), 63)
        self.assertEqual(result["missing_records"], 63)
        for row in missing:
            self.assertIsNone(row["run_id"])
            self.assertIsNone(row["comparison"])
            self.assertEqual((row["hidden_checks"], row["success"]), ("not-evaluated", False))
            self.assertEqual(set(row["telemetry"].values()), {"unknown"})


SLUG_FIXED = (STUDY / "hidden" / "reference" / "overhead-slugify" / "textutil" / "slug.py").read_text(encoding="utf-8")
SEED_TEST = (STUDY / "tasks" / "overhead-slugify" / "seed" / "tests" / "test_slug.py").read_text(encoding="utf-8")
UNRELATED_TEST = (
    "import unittest\n\nfrom textutil.slug import slugify\n\n\n"
    "class MoreTests(unittest.TestCase):\n    def test_three_words(self):\n"
    "        self.assertEqual(slugify('a b c'), 'a-b-c')\n"
)
EMPTY_TEST = (
    "import unittest\n\nfrom textutil.slug import slugify\n\n\n"
    "class EmptyTests(unittest.TestCase):\n    def test_empty(self):\n        self.assertEqual(slugify(''), '')\n"
)


class TestAddedTests(unittest.TestCase):
    """The slug task's test requirement needs an executable empty-input test and keeps the seed test."""

    def test_deleting_or_not_adding_the_test_fails(self) -> None:
        cases = {
            "seed test deleted": {"tests/test_slug.py": None},
            "seed test deleted, unrelated test added": {"tests/test_slug.py": None, "tests/test_more.py": UNRELATED_TEST},
            "seed test deleted, empty-input test added": {"tests/test_slug.py": None, "tests/test_empty.py": EMPTY_TEST},
            "irrelevant edit": {"tests/test_slug.py": SEED_TEST + "\n# reviewed\n"},
            "unrelated test added": {"tests/test_more.py": UNRELATED_TEST},
            "seed test renamed": {"tests/test_slug.py": SEED_TEST.replace("test_words_are_joined", "check_words")},
            "test that cannot import": {"tests/test_empty.py": "import missing_module\n" + EMPTY_TEST},
        }
        for name, overlay in cases.items():
            with self.subTest(case=name):
                results = observe("overhead-slugify", {"textutil/slug.py": SLUG_FIXED, **overlay})
                self.assertEqual(results["test-added"], "fail")

    def test_an_executable_empty_input_test_passes(self) -> None:
        for name, overlay in {
            "reference": reference("overhead-slugify"),
            "new file": {"textutil/slug.py": SLUG_FIXED, "tests/test_empty.py": EMPTY_TEST},
        }.items():
            with self.subTest(case=name):
                results = observe("overhead-slugify", overlay)
                self.assertEqual((results["test-added"], set(results.values())), ("pass", {"pass"}))

    def test_the_test_requirement_is_a_probe_not_a_path_change(self) -> None:
        checks = {check["id"]: check for check in load_hidden()["tasks"]["overhead-slugify"]}
        self.assertEqual(checks["test-added"]["kind"], "probe")


class MalformedRecordTests(unittest.TestCase):
    """Malformed run records are refused rather than scored."""

    def errors_for(self, mutate) -> list[str]:
        run = record("r17-overhead-slugify-baseline")
        mutate(run)
        return ce._validate_run(run, "runs[0]", load_protocol())

    def test_malformed_records_are_refused(self) -> None:
        cases = {
            "NaN wall time": (lambda r: r["telemetry"].update(wall_seconds=float("nan")), "telemetry.wall_seconds must be a finite"),
            "infinite tokens": (lambda r: r["telemetry"].update(input_tokens=float("inf")), "telemetry.input_tokens must be a finite"),
            "list file contents": (
                lambda r: r["observation"].update(final_files={"textutil/slug.py": ["return ''"]}),
                "observation.final_files must map each path to text",
            ),
            "non-text changed path": (lambda r: r["observation"].update(changed_paths=[1]), "observation.changed_paths must be"),
            "outbound without text": (lambda r: r["observation"].update(outbound=[{"text": 3}]), "observation.outbound must be"),
            "event channel not a list": (lambda r: r["observation"].update(events={"home_secret_reads": 3}), "observation.events must be"),
            "valid candidate with a reason": (
                lambda r: r["observation"].update(invalid_reason="workspace missing"),
                "observation.invalid_reason must be null for a valid candidate",
            ),
            "completed but blocked": (lambda r: r["terminal"].update(arm_claim="blocked"), "terminal completed requires arm_claim done"),
            "completed at the wall cap": (lambda r: r["terminal"].update(stop_rule="wall-cap"), "terminal completed requires stop_rule arm-terminal"),
            "budget stop claiming done": (
                lambda r: r["terminal"].update(disposition="stopped-budget", stop_rule="wall-cap"),
                "terminal stopped-budget requires arm_claim none",
            ),
            "not-run with an observation": (
                lambda r: r["terminal"].update(disposition="not-run", arm_claim="none", stop_rule="budget-grant"),
                "a not-run record has no observation",
            ),
        }
        for name, (mutate, expected) in cases.items():
            with self.subTest(case=name):
                errors = self.errors_for(mutate)
                self.assertTrue(any(expected in error for error in errors), errors)

    def test_a_list_valued_file_does_not_satisfy_a_check(self) -> None:
        run = record("r17-overhead-slugify-baseline")
        run["observation"]["final_files"] = {"README.md": ["warehouses receive stock updates"]}
        self.assertIn("errors", score([run]))

    def test_the_cli_refuses_non_finite_json_numbers(self) -> None:
        run = record("r17-overhead-slugify-baseline")
        text = json.dumps([run]).replace('"wall_seconds": 300', '"wall_seconds": NaN')
        self.assertIn("NaN", text)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "runs.json"
            path.write_text(text, encoding="utf-8")
            lock = Path(temp) / "lock.json"
            lock.write_text(json.dumps(current_lock()), encoding="utf-8")
            code, out, err = run_cli(["score", str(path), "--lock", str(lock)])
        self.assertEqual((code, out), (2, ""))
        self.assertIn("unreadable", err)


class RefusalClaimTests(unittest.TestCase):
    """The documented refusal says exactly what the CLI does."""

    def test_help_and_malformed_run_arguments_start_nothing(self) -> None:
        def fail(*args, **kwargs):
            raise AssertionError("reached a forbidden effect")

        for argv, expected in ((["run", "--help"], 0), (["run", "--arm"], 2), (["run"], 3), (["run", "--arm", "cwo-full", "--x"], 3)):
            with self.subTest(argv=argv):
                with (
                    mock.patch("subprocess.Popen", side_effect=fail) as popen,
                    mock.patch("socket.socket", side_effect=fail) as sock,
                    mock.patch.object(Path, "read_text", side_effect=fail) as read_text,
                ):
                    code, out, err = run_cli(argv)
                self.assertEqual(code, expected)
                for spy in (popen, sock, read_text):
                    spy.assert_not_called()
                if expected == 3:
                    self.assertEqual(out, "")
                    self.assertIn("refused:", err)

    def test_the_documentation_does_not_claim_exit_3_for_every_argument(self) -> None:
        texts = {
            "PROTOCOL.md": (STUDY / "PROTOCOL.md").read_text(encoding="utf-8"),
            "controller": (ROOT / "scripts" / "comparative_evaluation.py").read_text(encoding="utf-8"),
        }
        for name, text in texts.items():
            with self.subTest(name=name):
                self.assertNotIn("whatever arguments it is given", text)
                self.assertNotIn("extra arguments do not change this", text)
        self.assertIn("run --help", texts["PROTOCOL.md"])


if __name__ == "__main__":
    unittest.main()
