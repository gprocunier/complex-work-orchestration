"""Bead IDs reach ``bd`` as operands, never as options.

Every ``bd`` call puts all options and option values before ``--`` and the
Bead IDs after it. The real-``bd`` tests below run complete commands in a
disposable database: ordinary IDs keep their exact semantics, and option-like
IDs fail without changing the database (a full export is compared before and
after). The fake-runner tests pin the full argv of each call site.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import close_bead_with_summary  # noqa: E402
from build_beads_brief import build_brief  # noqa: E402
from close_bead_with_summary import PartialPersistence, execute  # noqa: E402
from continue_sprint import load_beads_items  # noqa: E402
from cwo_core import beads  # noqa: E402
from cwo_core.beads import add_dependency, show_bead_exact_structured, show_bead_json  # noqa: E402
from cwo_core.native_pool_admission import BeadsClaimAdapter, NativePoolAdmissionError  # noqa: E402
from tests.real_beads_fixture import (  # noqa: E402
    REAL_BEADS_FIXTURE_TIMEOUT_SECONDS,
    initialize_real_beads,
    run_fixture_subprocess,
)
from tests.real_beads_fixture import configure_git_fixture

BD_PATH = shutil.which("bd")
OPTION_LIKE_IDS = ("--help", "-fake")
SHOW_FLAG_COMBINATIONS = ((False, False), (True, False), (False, True), (True, True))


AUTHORIZATION_DRIVER = """\
import runpy,sys
from pathlib import Path
script,host_root,*arguments = sys.argv[1:]
sys.path.insert(0,str(Path(script).parent))
from cwo_core.host_records import HostRecordStore,using_test_store
sys.argv=[script,*arguments]
with using_test_store(HostRecordStore.for_tests(Path(host_root))):
    runpy.run_path(script,run_name='__main__')
"""


def closure_args(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "bead": "",
        "disposition": "superseded",
        "why": "policy helper added",
        "who_involved": ["Project lead"],
        "what_changed": ["closure helper documents richer durable memory"],
        "how_validated": ["python -m unittest tests/test_beads_dash_id_safety.py"],
        "when_closed": ["main at HEAD"],
        "where_executed": ["disposable Beads database"],
        "decision": ["close reason stays terse"],
        "evidence": ["python -m unittest tests/test_beads_dash_id_safety.py"],
        "residual_risk": ["none known"],
        "follow_up": ["none"],
        "close": False,
        "close_reason": None,
        "dry_run": False,
        "json": False,
        "meaningful": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class BeadsArgvShapeTests(unittest.TestCase):
    """Full argv of each call site: options first, then ``--``, then IDs."""

    def test_show_args_put_every_option_before_the_separator(self) -> None:
        expected = {
            (False, False): ["show", "--json", "--", "-x"],
            (True, False): ["show", "--json", "--include-comments", "--", "-x"],
            (False, True): ["show", "--json", "--include-dependents", "--", "-x"],
            (True, True): ["show", "--json", "--include-comments", "--include-dependents", "--", "-x"],
        }
        for (comments, dependents), argv in expected.items():
            with self.subTest(comments=comments, dependents=dependents):
                self.assertEqual(
                    beads.show_bead_args("-x", include_comments=comments, include_dependents=dependents),
                    argv,
                )
                with mock.patch("cwo_core.beads.run_bd", return_value="[]") as run_bd:
                    show_bead_json("-x", include_comments=comments, include_dependents=dependents)
                run_bd.assert_called_once_with(argv)

    def test_dependency_refuses_option_like_ids_before_bd_runs(self) -> None:
        for blocked, blocker in (("-blocked", "cwo-blocker"), ("cwo-blocked", "-blocker"), ("--help", "--help")):
            with self.subTest(blocked=blocked, blocker=blocker), \
                    mock.patch("cwo_core.beads.run_bd") as run_bd, \
                    self.assertRaisesRegex(ValueError, "refusing option-like Bead ID"):
                add_dependency(blocked, blocker, dependency_type="tracks")
            run_bd.assert_not_called()

    def test_exact_structured_show_puts_json_before_the_separator(self) -> None:
        completed = subprocess.CompletedProcess([], 0, stdout='[{"id": "-x"}]', stderr="")
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch("cwo_core.beads.require_bd"), \
                mock.patch("cwo_core.beads.subprocess.run", return_value=completed) as run:
            result, issue = show_bead_exact_structured("-x", directory=directory, database="db", actor="tester")
        expected = ("bd", "-C", str(Path(directory).absolute()), "--db", "db", "--actor", "tester",
                    "show", "--json", "--", "-x")
        self.assertEqual(run.call_args.args[0], expected)
        self.assertEqual(result.command, expected)
        self.assertEqual(issue, {"id": "-x"})
        self.assertEqual(run.call_args.kwargs, {
            "check": False, "cwd": Path(directory).absolute(), "text": True,
            "stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "timeout": 300,
        })
        # Each invalid explicit input must stop the process itself, including
        # when a caller selects a write. The valid control above reaches it.
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(beads, "require_bd"):
            valid = {"directory": directory, "database": "db", "actor": "tester"}
            for label, overrides, argv in (
                ("directory", {"directory": str(Path(directory) / "missing")}, ["close", "x"]),
                ("database", {"database": " "}, ["close", "x"]),
                ("actor", {"actor": " "}, ["close", "x"]),
                ("empty-argv", {}, []),
                ("string-argv", {}, "close"),
                ("empty-argument", {}, ["close", ""]),
            ):
                with self.subTest(explicit_input=label), \
                        mock.patch.object(beads.subprocess, "run", return_value=completed) as effect:
                    failure = None
                    try:
                        beads.run_bd_structured(argv, **(valid | overrides))
                    except ValueError as exc:
                        failure = exc
                    effect.assert_not_called()
                    self.assertIsInstance(failure, ValueError)

        # The public structured boundary reports absent bd before attempting
        # any child. A present executable still reaches the original command
        # exactly once with the same observable result.
        with tempfile.TemporaryDirectory() as directory:
            arguments = {"directory": directory, "database": "db", "actor": "tester"}
            with mock.patch.object(beads.shutil, "which", return_value=None), \
                    mock.patch.object(beads.subprocess, "run", return_value=completed) as effect:
                failure = None
                try:
                    beads.run_bd_structured(["show", "--json", "--", "cwo-positive"], **arguments)
                except SystemExit as exc:
                    failure = str(exc)
                self.assertEqual(failure, "bd was not found; install Beads or use --dry-run")
                effect.assert_not_called()
            with mock.patch.object(beads.shutil, "which", return_value="/fixture/bd"), \
                    mock.patch.object(beads.subprocess, "run", return_value=completed) as effect:
                result = beads.run_bd_structured(["show", "--json", "--", "cwo-positive"], **arguments)
                effect.assert_called_once()
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout, completed.stdout)
                self.assertEqual(effect.call_args.args[0],
                                 ("bd", "-C", str(Path(directory).absolute()), "--db", "db",
                                  "--actor", "tester", "show", "--json", "--", "cwo-positive"))

    def test_brief_displays_the_command_it_runs(self) -> None:
        expected = {
            "summary": ["bd", "show", "--json", "--", "cwo-1"],
            "focused": ["bd", "show", "--json", "--include-comments", "--", "cwo-1"],
            "audit": ["bd", "show", "--json", "--include-comments", "--include-dependents", "--", "cwo-1"],
        }
        for depth, command in expected.items():
            with self.subTest(depth=depth), mock.patch("cwo_core.beads.run_bd", return_value='[{"id": "cwo-1"}]') as run_bd:
                brief = build_brief("cwo-1", depth=depth, audience="main-thread")
            self.assertEqual(brief["bd_command"], command)
            run_bd.assert_called_once_with(command[1:])


    def test_dependency_type_precedes_the_separator(self) -> None:
        with mock.patch("cwo_core.beads.run_bd", return_value="") as run_bd:
            add_dependency("cwo-blocked", "cwo-blocker", dependency_type="Tracks")
        run_bd.assert_called_once_with(["dep", "add", "--type", "tracks", "--", "cwo-blocked", "cwo-blocker"])


@unittest.skipUnless(BD_PATH, "bd CLI not available")
class RealBeadsBoundaryTests(unittest.TestCase):
    """Complete commands against the real ``bd`` in a disposable database."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="cwo-beadid-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        run_fixture_subprocess(["git", "init", "-q"], cwd=self.root, check=True)
        configure_git_fixture(self.root)
        initialize_real_beads(
            [BD_PATH or "bd", "init", "--non-interactive", "--skip-agents", "--skip-hooks", "-p", "cwo"],
            cwd=self.root,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        overrides = {
            "BEADS_DIR": str(self.root / ".beads"),
            "CWO_BEADS_TIMEOUT_SECONDS": str(REAL_BEADS_FIXTURE_TIMEOUT_SECONDS),
        }
        self.env = {**os.environ, **overrides}
        patcher = mock.patch.dict(os.environ, overrides)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.alpha = self.bd("create", "Alpha", "--type", "task", "--silent")
        self.beta = self.bd("create", "Beta", "--type", "task", "--silent")
        self.gamma = self.bd("create", "Gamma", "--type", "task", "--silent")

    def bd(self, *args: str) -> str:
        return run_fixture_subprocess(
            [BD_PATH or "bd", *args],
            cwd=self.root,
            env=self.env,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout.strip()

    def export(self) -> dict[str, dict]:
        """Every issue with its labels, dependencies and comments, keyed by ID."""

        records = [json.loads(line) for line in self.bd("export").splitlines() if line.strip()]
        return {record["id"]: record for record in records}

    def assert_only_changed(self, before: dict[str, dict], after: dict[str, dict], changed: set[str]) -> None:
        self.assertEqual(set(after), set(before))
        for issue_id in before:
            if issue_id not in changed:
                self.assertEqual(after[issue_id], before[issue_id], issue_id)
        for issue_id in changed:
            self.assertNotEqual(after[issue_id], before[issue_id], issue_id)

    def adapter(self) -> BeadsClaimAdapter:
        return BeadsClaimAdapter(
            directory=self.root,
            database=self.root / ".beads" / "embeddeddolt",
            actor="beadid-boundary-test",
            timeout=REAL_BEADS_FIXTURE_TIMEOUT_SECONDS,
        )

    # show

    def test_show_ordinary_id_with_each_optional_flag_returns_json(self) -> None:
        self.bd("comment", "--", self.alpha, "fixture comment")
        self.bd("dep", "add", "--", self.beta, self.alpha)
        before = self.export()
        for comments, dependents in SHOW_FLAG_COMBINATIONS:
            with self.subTest(comments=comments, dependents=dependents):
                payload = show_bead_json(self.alpha, include_comments=comments, include_dependents=dependents)
                self.assertIsInstance(payload, list)
                self.assertEqual([item["id"] for item in payload], [self.alpha])
                issue = payload[0]
                if comments:
                    self.assertEqual([item["text"] for item in issue["comments"]], ["fixture comment"])
                else:
                    self.assertNotIn("comments", issue)
                if dependents:
                    self.assertEqual([item["id"] for item in issue["dependents"]], [self.beta])
                else:
                    self.assertNotIn("dependents", issue)
        self.assertEqual(self.export(), before)

    def test_exact_structured_show_reads_one_issue_and_refuses_option_like_ids(self) -> None:
        database = self.root / ".beads" / "embeddeddolt"
        result, issue = show_bead_exact_structured(self.alpha, directory=self.root, database=database, actor="t")
        self.assertTrue(result.succeeded, result.stderr)
        self.assertEqual(result.command[-4:], ("show", "--json", "--", self.alpha))
        self.assertEqual(issue["id"], self.alpha)
        before = self.export()
        for bead_id in OPTION_LIKE_IDS:
            with self.subTest(bead_id=bead_id):
                result, issue = show_bead_exact_structured(bead_id, directory=self.root, database=database, actor="t")
                self.assertFalse(result.succeeded)
                self.assertEqual(result.returncode, 1)
                self.assertIsNone(issue)
        self.assertEqual(self.export(), before)

    # dep add

    def test_dependency_types_persist_and_change_only_the_blocked_bead(self) -> None:
        for dependency_type, blocked, blocker in (
            ("tracks", self.alpha, self.beta),
            ("Validates", self.gamma, self.beta),
            ("blocks", self.beta, self.alpha),
        ):
            with self.subTest(dependency_type=dependency_type):
                before = self.export()
                add_dependency(blocked, blocker, dependency_type=dependency_type)
                after = self.export()
                if dependency_type == "blocks":
                    # Only a blocking edge counts toward the blocker's dependents.
                    self.assertEqual(after[blocker]["dependent_count"], before[blocker]["dependent_count"] + 1)
                    after[blocker]["dependent_count"] = before[blocker]["dependent_count"]
                self.assert_only_changed(before, after, {blocked})
                self.assertEqual(
                    [(item["depends_on_id"], item["type"]) for item in after[blocked]["dependencies"]],
                    [(blocker, dependency_type.lower())],
                )

    # comment and close

    def test_comment_posts_the_summary_on_exactly_one_bead(self) -> None:
        before = self.export()
        result = execute(closure_args(bead=self.alpha, disposition="deferred"))
        after = self.export()
        self.assert_only_changed(before, after, {self.alpha})
        self.assertEqual([item["text"] for item in after[self.alpha]["comments"]], [result["summary"]])
        self.assertEqual(after[self.alpha]["status"], "open")

    def test_close_with_reason_stores_the_reason_on_exactly_one_bead(self) -> None:
        before = self.export()
        result = execute(closure_args(bead=self.beta, close=True))
        after = self.export()
        self.assertTrue(result["closed"])
        self.assert_only_changed(before, after, {self.beta})
        self.assertEqual(after[self.beta]["status"], "closed")
        self.assertEqual(after[self.beta]["close_reason"], "superseded: policy helper added")
        self.assertEqual([item["text"] for item in after[self.beta]["comments"]], [result["summary"]])

    def test_comment_and_close_with_option_like_ids_fail_without_changes(self) -> None:
        before = self.export()
        for bead_id in OPTION_LIKE_IDS:
            with self.subTest(bead_id=bead_id), self.assertRaises(SystemExit):
                execute(closure_args(bead=bead_id, close=True))
        self.assertEqual(self.export(), before)

    def test_close_step_with_option_like_ids_fails_without_changes(self) -> None:
        real_run_bd = close_bead_with_summary.run_bd

        def skip_comment(command: list[str]) -> str:
            return "ok" if command[0] == "comment" else real_run_bd(command)

        before = self.export()
        for bead_id in OPTION_LIKE_IDS:
            with self.subTest(bead_id=bead_id), \
                    mock.patch("close_bead_with_summary.run_bd", side_effect=skip_comment), \
                    self.assertRaises(PartialPersistence) as raised:
                execute(closure_args(bead=bead_id, close=True))
            self.assertIn(bead_id, raised.exception.result["close_error"])
        self.assertEqual(self.export(), before)

    # update (admission claim and close, Sol break-fix authorization)

    def test_admission_claim_and_close_change_exactly_one_bead(self) -> None:
        adapter = self.adapter()
        before = self.export()
        claim = adapter.claim(self.gamma)
        self.assertTrue(claim.owned)
        close = adapter.close_owned(
            self.gamma,
            expected_pre_show_sha256=claim.receipt["post_show_sha256"],
            reason="boundary close",
        )
        self.assertTrue(close.closed)
        after = self.export()
        self.assert_only_changed(before, after, {self.gamma})
        self.assertEqual(after[self.gamma]["status"], "closed")
        self.assertEqual(after[self.gamma]["close_reason"], "boundary close")

    def test_admission_refuses_option_like_ids_without_changes(self) -> None:
        adapter = self.adapter()
        before = self.export()
        for bead_id in OPTION_LIKE_IDS:
            with self.subTest(bead_id=bead_id):
                for attempt in (
                    lambda: adapter.show_exact(bead_id),
                    lambda: adapter.claim(bead_id),
                    lambda: adapter.close_owned(bead_id, expected_pre_show_sha256="0" * 64, reason="r"),
                ):
                    with self.assertRaisesRegex(NativePoolAdmissionError, f"^exact-show-failed:{bead_id}$"):
                        attempt()
        self.assertEqual(self.export(), before)

    def authorize(self, bead_id: str) -> subprocess.CompletedProcess[str]:
        return run_fixture_subprocess(
            [
                sys.executable,
                "-I", "-B", "-c", AUTHORIZATION_DRIVER,
                str(ROOT / "scripts" / "authorize_sol_breakfix.py"),
                str(self.root / "audit-host"),
                "--allow-sol-breakfix",
                "--operator-approval-ref=current-chat-turn",
                f"--bead={bead_id}",
                "--incident-kind=self-hosting-orchestration",
                "--scope=self-hosting incident repair",
                f"--expires-after-bead={bead_id}",
                "--waiver-reason=boundary test",
            ],
            cwd=self.root,
            env=self.env,
            capture_output=True,
            text=True,
        )

    def test_sol_breakfix_authorization_updates_exactly_one_bead(self) -> None:
        before = self.export()
        completed = self.authorize(self.alpha)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        after = self.export()
        self.assert_only_changed(before, after, {self.alpha})
        self.assertEqual(after[self.alpha]["labels"], ["sol-breakfix-approved"])
        self.assertTrue(after[self.alpha]["notes"].startswith("SOL BREAK-FIX AUTHORIZED: approval=current-chat-turn;"))
        self.assertTrue((self.root / "audit-host" / "audit.jsonl").is_file())

    def test_sol_breakfix_authorization_with_option_like_ids_fails_without_changes(self) -> None:
        before = self.export()
        for bead_id in OPTION_LIKE_IDS:
            with self.subTest(bead_id=bead_id):
                completed = self.authorize(bead_id)
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertIn(f'no issue found matching "{bead_id}"', completed.stderr)
        self.assertEqual(self.export(), before)
        self.assertFalse((self.root / "audit.jsonl").exists())

    # show of a discovered epic (sprint continuation)

    def test_continuation_with_option_like_epic_fails_without_changes(self) -> None:
        before = self.export()
        for epic_id in OPTION_LIKE_IDS:
            with self.subTest(epic_id=epic_id), self.assertRaises(SystemExit) as raised:
                load_beads_items(epic_id)
            self.assertIn(epic_id, str(raised.exception))
        self.assertEqual(self.export(), before)


    def test_show_option_like_ids_fail_without_changes(self) -> None:
        before = self.export()
        for bead_id in OPTION_LIKE_IDS:
            for comments, dependents in SHOW_FLAG_COMBINATIONS:
                with self.subTest(bead_id=bead_id, comments=comments, dependents=dependents):
                    with self.assertRaises(SystemExit):
                        show_bead_json(bead_id, include_comments=comments, include_dependents=dependents)
        self.assertEqual(self.export(), before)

    def test_brief_reads_the_real_bead(self) -> None:
        self.bd("comment", "--", self.alpha, "brief comment")
        brief = build_brief(self.alpha, depth="audit", audience="main-thread")
        self.assertEqual(brief["bd_command"][-2:], ["--", self.alpha])
        self.assertEqual(brief["entries"][0]["id"], self.alpha)
        self.assertIn("brief comment", json.dumps(brief["entries"]))


    def test_dependency_with_option_like_ids_is_refused_without_changes(self) -> None:
        # bd stores an unresolved nonblocking depends-on ID as given, even
        # after "--", so the refusal must come before bd runs.
        before = self.export()
        for bead_id in OPTION_LIKE_IDS:
            for dependency_type in ("tracks", "blocks"):
                for blocked, blocker in ((bead_id, self.beta), (self.alpha, bead_id)):
                    with self.subTest(blocked=blocked, blocker=blocker, dependency_type=dependency_type), \
                            self.assertRaisesRegex(ValueError, "refusing option-like Bead ID"):
                        add_dependency(blocked, blocker, dependency_type=dependency_type)
        self.assertEqual(self.export(), before)


if __name__ == "__main__":
    unittest.main()
