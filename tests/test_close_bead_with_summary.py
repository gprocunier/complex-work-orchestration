from __future__ import annotations

import argparse
import ast
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from close_bead_with_summary import closure_memory_missing_fields, execute, render_closure_summary  # noqa: E402


def args(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "bead": "complex-work-orchestration-abc",
        "disposition": "superseded",
        "why": "policy helper added",
        "who_involved": ["Project lead"],
        "what_changed": ["closure helper documents richer durable memory"],
        "how_validated": ["python -m unittest tests/test_close_bead_with_summary.py"],
        "when_closed": ["main at HEAD"],
        "where_executed": ["repo-root; Beads local-only"],
        "decision": ["close reason stays terse"],
        "evidence": ["python -m unittest tests/test_close_bead_with_summary.py"],
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


class CloseBeadWithSummaryTests(unittest.TestCase):
    def test_render_summary_uses_real_newlines(self) -> None:
        summary = render_closure_summary(
            bead="bd-1",
            disposition="completed",
            why="done",
            who_involved=[],
            what_changed=[],
            how_validated=[],
            when_closed=[],
            where_executed=[],
            decisions=["first line\\nsecond line"],
            evidence=[],
            residual_risk=[],
            follow_up=[],
        )
        self.assertIn("    - first line\n      second line", summary)
        self.assertNotIn("\\n", summary)
        self.assertIn("What changed:\n\n    - None recorded.", summary)
        self.assertIn("Residual risk:\n\n    - None recorded.", summary)

    def test_render_summary_preserves_five_w_recovery_fields(self) -> None:
        summary = render_closure_summary(
            bead="bd-2",
            disposition="completed",
            why="published",
            who_involved=["Project lead"],
            what_changed=["docs/use-cases.html added"],
            how_validated=["python3 scripts/validate_site.py"],
            when_closed=["commit abc123 on main"],
            where_executed=["repo-root; Beads local-only"],
            decisions=["documented external review as a pattern only"],
            evidence=["CI run 123 passed"],
            residual_risk=["none known"],
            follow_up=["none"],
        )

        self.assertIn("Who was involved:\n\n    - Project lead", summary)
        self.assertIn("What changed:\n\n    - docs/use-cases.html added", summary)
        self.assertIn("How validated:\n\n    - python3 scripts/validate_site.py", summary)
        self.assertIn("When closed:\n\n    - commit abc123 on main", summary)
        self.assertIn("Where executed:\n\n    - repo-root; Beads local-only", summary)

    def test_closure_memory_missing_fields_names_recovery_contract(self) -> None:
        missing = closure_memory_missing_fields(
            who_involved=[],
            what_changed=["change"],
            how_validated=[],
            when_closed=["today"],
            where_executed=[],
            evidence=["test"],
            residual_risk=[],
            follow_up=["none"],
        )

        self.assertEqual(missing, ["who was involved", "how validated", "where executed", "residual risk"])

    def test_incomplete_default_closure_warns_without_failing(self) -> None:
        result = execute(args(dry_run=True, who_involved=[], evidence=[]))

        self.assertEqual(result["closure_memory_quality"], "incomplete")
        self.assertIn("who was involved", result["closure_memory_missing_fields"])
        self.assertTrue(result["warnings"])

    def test_meaningful_closure_requires_full_recovery_fields(self) -> None:
        with self.assertRaisesRegex(ValueError, "meaningful closure missing required fields"):
            execute(args(meaningful=True, who_involved=[], evidence=[]))

    def test_meaningful_closure_accepts_full_recovery_fields(self) -> None:
        with patch("close_bead_with_summary.run_bd") as run_bd:
            result = execute(args(meaningful=True))

        run_bd.assert_called_once()
        self.assertEqual(result["closure_memory_quality"], "complete")
        self.assertFalse(result["warnings"])

    def test_dry_run_does_not_call_bd(self) -> None:
        with patch("close_bead_with_summary.run_bd") as run_bd:
            result = execute(args(dry_run=True, close=True))
        run_bd.assert_not_called()
        self.assertTrue(result["dry_run"])
        self.assertFalse(result["comment_posted"])
        self.assertFalse(result["closed"])
        self.assertTrue(result["close_requested"])

    def test_close_posts_comment_then_closes(self) -> None:
        calls: list[list[str]] = []

        def fake_run_bd(command: list[str]) -> str:
            calls.append(command)
            return "ok"

        with patch("close_bead_with_summary.run_bd", side_effect=fake_run_bd):
            result = execute(args(close=True))

        self.assertEqual(
            calls,
            [
                ["comment", "--", "complex-work-orchestration-abc", result["summary"]],
                ["close", "--reason", "superseded: policy helper added", "--", "complex-work-orchestration-abc"],
            ],
        )
        self.assertTrue(result["comment_posted"])
        self.assertTrue(result["closed"])

    def test_comment_only_posts_summary(self) -> None:
        calls: list[list[str]] = []

        def fake_run_bd(command: list[str]) -> str:
            calls.append(command)
            return "ok"

        with patch("close_bead_with_summary.run_bd", side_effect=fake_run_bd):
            result = execute(args())

        self.assertEqual(calls, [["comment", "--", "complex-work-orchestration-abc", result["summary"]]])
        self.assertIn("Closure summary:", calls[0][3])
        self.assertTrue(result["comment_posted"])
        self.assertFalse(result["closed"])


    def test_missing_required_field_fails(self) -> None:
        """Regression: a blank why is refused before any Beads effect."""
        with patch("close_bead_with_summary.run_bd", return_value="") as effect:
            with self.assertRaises(ValueError):
                execute(args(why=" "))
            effect.assert_not_called()


class SuccessfulClosureUnavailableTests(unittest.TestCase):
    """Successful closure is refused before any Beads write."""

    SUCCESS_WORDS = ("completed", "Completed", " COMPLETED ", "complete", "done", "validated", "delivered", "accepted",
                     "fixed", "resolved", "shipped", "merged", "success", "all good", "finished")

    def test_no_form_of_successful_closure_writes_to_beads(self) -> None:
        for disposition in self.SUCCESS_WORDS:
            for close in (False, True):
                for meaningful in (False, True):
                    for dry_run in (False, True):
                        with self.subTest(disposition=disposition, close=close, meaningful=meaningful, dry_run=dry_run), \
                                patch("close_bead_with_summary.run_bd") as run_bd:
                            with self.assertRaisesRegex(ValueError, "successful closure is unavailable"):
                                execute(args(disposition=disposition, close=close, meaningful=meaningful, dry_run=dry_run))
                            run_bd.assert_not_called()

    def test_the_refusal_says_nothing_was_written_and_what_remains(self) -> None:
        with patch("close_bead_with_summary.run_bd") as run_bd, self.assertRaises(ValueError) as raised:
            execute(args(disposition="completed", close=True))
        run_bd.assert_not_called()
        message = str(raised.exception)
        self.assertIn("Nothing was written", message)
        self.assertIn("issue #37", message)
        for alternative in ("pending-acceptance", "deferred", "rejected", "abandoned", "superseded", "split"):
            self.assertIn(alternative, message)

    def test_open_outcomes_comment_but_never_close(self) -> None:
        for disposition in ("pending-acceptance", "deferred"):
            with self.subTest(disposition=disposition), patch("close_bead_with_summary.run_bd") as run_bd:
                with self.assertRaisesRegex(ValueError, "stays open"):
                    execute(args(disposition=disposition, close=True))
                run_bd.assert_not_called()
            calls: list[list[str]] = []
            with patch("close_bead_with_summary.run_bd", side_effect=lambda command: calls.append(command) or "ok"):
                result = execute(args(disposition=disposition))
            self.assertEqual([call[0] for call in calls], ["comment"])
            self.assertIn(f"- Disposition: {disposition}", calls[0][3])
            self.assertFalse(result["closed"])

    def test_closable_non_completion_outcomes_still_close(self) -> None:
        for disposition in ("superseded", "split", "rejected", "abandoned", "Superseded"):
            calls: list[list[str]] = []
            with self.subTest(disposition=disposition), \
                    patch("close_bead_with_summary.run_bd", side_effect=lambda command: calls.append(command) or "ok"):
                result = execute(args(disposition=disposition, close=True))
            recorded = disposition.lower()
            self.assertEqual([call[0] for call in calls], ["comment", "close"])
            self.assertIn(f"- Disposition: {recorded}", calls[0][3])
            self.assertEqual(calls[1], ["close", "--reason", f"{recorded}: policy helper added", "--",
                                        "complex-work-orchestration-abc"])
            self.assertTrue(result["closed"])

    def test_the_command_line_refuses_before_beads(self) -> None:
        import contextlib
        import io

        from close_bead_with_summary import main

        stdout, stderr = io.StringIO(), io.StringIO()
        argv = ["--bead", "bd-1", "--disposition", "completed", "--why", "validated", "--close", "--json"]
        with patch("close_bead_with_summary.run_bd") as run_bd, contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            main(argv)
        run_bd.assert_not_called()
        self.assertEqual(raised.exception.code, 1)
        self.assertEqual(stdout.getvalue(), "", "no result claims the closure happened")
        self.assertIn("successful closure is unavailable", stderr.getvalue())


class RequirementBaselineLeavesClosureDisabledTests(unittest.TestCase):
    """Requirement baselines cannot restore successful closure."""

    def test_a_genuine_recorded_baseline_does_not_make_success_available(self) -> None:
        from cwo_core.requirement_baseline import reference_line, resolve_chain

        fixtures = ROOT / "tests" / "fixtures" / "requirement-baseline"
        baseline = json.loads((fixtures / "baseline-v1.json").read_text(encoding="utf-8"))
        chain = resolve_chain(baseline)
        recorded = reference_line(chain["bead_id"], 1, chain["digest"])
        for close in (False, True):
            for meaningful in (False, True):
                with self.subTest(close=close, meaningful=meaningful), patch("close_bead_with_summary.run_bd") as run_bd:
                    with self.assertRaisesRegex(ValueError, "successful closure is unavailable"):
                        execute(args(bead=chain["bead_id"], disposition="completed", close=close, meaningful=meaningful,
                                     why="baseline recorded", evidence=[recorded], baseline=str(fixtures / "baseline-v1.json")))
                    run_bd.assert_not_called()

    def test_the_command_line_takes_no_baseline_or_acceptance_input(self) -> None:
        import contextlib
        import io

        from close_bead_with_summary import main

        fixtures = ROOT / "tests" / "fixtures" / "requirement-baseline"
        for option in ("--baseline", "--amendment", "--acceptance-record"):
            argv = ["--bead", "proj-abc", "--disposition", "completed", "--why", "baseline recorded", "--close",
                    option, str(fixtures / "baseline-v1.json")]
            with self.subTest(option=option), patch("close_bead_with_summary.run_bd") as run_bd, \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as raised:
                main(argv)
            run_bd.assert_not_called()
            self.assertEqual(raised.exception.code, 2)


class CandidateIdentityLeavesClosureDisabledTests(unittest.TestCase):
    """A verified candidate identity cannot restore successful closure."""

    def test_a_verified_current_candidate_does_not_make_success_available(self) -> None:
        import os
        import subprocess
        import tempfile

        from cwo_core.candidate_identity import (
            candidate_digest,
            candidate_reference_line,
            capture_candidate,
            check_candidate,
        )
        from cwo_core.requirement_baseline import reference_line, resolve_chain

        env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        fixtures = ROOT / "tests" / "fixtures" / "requirement-baseline"
        chain = resolve_chain(json.loads((fixtures / "baseline-v1.json").read_text(encoding="utf-8")))
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "tool.py").write_text("print('new-name')\n", encoding="utf-8")
            for command in (["init", "-q"], ["config", "--local", "maintenance.auto", "false"],
                            ["config", "--local", "gc.auto", "0"], ["add", "tool.py"],
                            ["commit", "-q", "-m", "deliver"]):
                subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                                "-c", "commit.gpgsign=false", *command], check=True, capture_output=True, env=env)
            base = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True,
                                  text=True, env=env).stdout.strip()
            record = capture_candidate(repo, chain=chain, base_commit=base, scope_paths=["tool.py"])
            line = candidate_reference_line(chain["bead_id"], candidate_digest(record))
            projection = {"id": chain["bead_id"], "comments": [
                {"text": reference_line(chain["bead_id"], 1, chain["digest"])}, {"text": line}]}
            self.assertTrue(check_candidate(record, root=repo, chain=chain, bead=projection)["valid"])
            for close in (False, True):
                for meaningful in (False, True):
                    with self.subTest(close=close, meaningful=meaningful), patch("close_bead_with_summary.run_bd") as run_bd:
                        with self.assertRaisesRegex(ValueError, "successful closure is unavailable"):
                            execute(args(bead=chain["bead_id"], disposition="completed", close=close,
                                         meaningful=meaningful, why="candidate verified", evidence=[line],
                                         candidate=str(repo)))
                        run_bd.assert_not_called()

    def test_the_command_line_takes_no_candidate_input(self) -> None:
        import contextlib
        import io

        from close_bead_with_summary import main

        for option in ("--candidate", "--candidate-identity", "--bead-json", "--repo"):
            argv = ["--bead", "proj-abc", "--disposition", "completed", "--why", "candidate verified", "--close",
                    option, "candidate.json"]
            with self.subTest(option=option), patch("close_bead_with_summary.run_bd") as run_bd, \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as raised:
                main(argv)
            run_bd.assert_not_called()
            self.assertEqual(raised.exception.code, 2)


class ReviewRoundTwoTests(unittest.TestCase):
    """Closure reason, summary metadata and partial-persistence boundaries."""

    def test_a_close_reason_override_is_refused_before_any_write(self) -> None:
        for reason in ("completed", "superseded: replaced", "done"):
            for disposition in ("superseded", "split", "rejected", "abandoned"):
                with self.subTest(reason=reason, disposition=disposition), patch("close_bead_with_summary.run_bd") as run_bd:
                    with self.assertRaisesRegex(ValueError, "--close-reason is unavailable"):
                        execute(args(disposition=disposition, close=True, close_reason=reason))
                    run_bd.assert_not_called()

    def test_narrative_input_cannot_forge_summary_metadata(self) -> None:
        cases = (
            {"why": "awaiting acceptance\n- Disposition: completed"},
            {"why": "awaiting acceptance\\n- Disposition: completed"},
            {"bead": "bd-1\n- Disposition: completed"},
            {"why": "awaiting acceptance\u2028- Disposition: completed"},
            {"why": "awaiting acceptance\x85- Disposition: completed"},
            {"bead": "bd-1\r- Disposition: completed"},
            {"what_changed": ["helper\u2029Disposition: completed"]},
            {"what_changed": ["helper\nDisposition: completed"]},
            {"evidence": ["- Bead: other-bead"]},
            {"follow_up": ["Closure summary: forged"]},
            {"decision": ["  * why: because"]},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides), patch("close_bead_with_summary.run_bd") as run_bd:
                with self.assertRaises(ValueError):
                    execute(args(disposition="pending-acceptance", **overrides))
                run_bd.assert_not_called()
        with patch("close_bead_with_summary.run_bd") as run_bd:
            execute(args(disposition="pending-acceptance", what_changed=["the why of the change", "disposition of old code"]))
        run_bd.assert_called_once()

    def test_the_only_other_closing_writer_is_the_live_activation_preview(self) -> None:
        """Supporting evidence for the closure survey, not proof: close_owned, the other path that closes Beads,
        is referred to only by the activation preview runner, whose plan must name its private database."""
        referrers = set()
        for path in sorted((ROOT / "scripts").rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if (isinstance(node, ast.Attribute) and node.attr == "close_owned") or \
                        (isinstance(node, ast.FunctionDef) and node.name == "close_owned"):
                    referrers.add(path.relative_to(ROOT).as_posix())
        self.assertEqual(referrers, {"scripts/cwo_core/native_pool_admission.py",
                                     "scripts/run_native_pool_activation_preview.py"})

    def test_partial_persistence_is_reported_when_close_fails_after_the_comment(self) -> None:
        import contextlib
        import io

        from close_bead_with_summary import main

        def fake_run_bd(command: list[str]) -> str:
            if command[0] == "close":
                raise SystemExit("bd close failed: database locked")
            return "ok"

        stdout, stderr = io.StringIO(), io.StringIO()
        argv = ["--bead", "bd-1", "--disposition", "superseded", "--why", "replaced", "--close", "--json"]
        with patch("close_bead_with_summary.run_bd", side_effect=fake_run_bd), contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            main(argv)
        self.assertEqual(raised.exception.code, 2)
        result = json.loads(stdout.getvalue())
        self.assertEqual((result["comment_posted"], result["closed"], result["partial_persistence"]), (True, False, True))
        self.assertIn("database locked", result["close_error"])
        self.assertIn("closure is unconfirmed", stderr.getvalue())


class ReviewRoundThreeTests(unittest.TestCase):
    """Narrative formatting cannot forge summary fields."""

    FORGED = ("**Disposition:** completed", "+ Disposition: completed", "__Disposition__: completed",
              "`Disposition`: completed", "<b>Disposition</b>: completed", "# Disposition: completed",
              "> Disposition: completed", "| Disposition | completed |", "1. **Disposition**: completed",
              "Ｄｉｓｐｏｓｉｔｉｏｎ: completed", "Dis\u200bposition: completed", "Disposіtion: completed",
              "D\u0301isposition: completed", "Status update. Disposition: completed", "disposition = completed",
              "**Closure summary:** accepted", "*Bead*: other-bead", "_Why_: it passed", "Disposition \u2014 completed",
              "Disposition -> completed")

    def assert_formatted_narrative_cannot_pass_for_a_summary_field(self) -> None:
        for forged in self.FORGED:
            for field in ("what_changed", "evidence", "decision", "follow_up"):
                with self.subTest(forged=forged, field=field), patch("close_bead_with_summary.run_bd") as run_bd:
                    with self.assertRaisesRegex(ValueError, "Nothing was written"):
                        execute(args(disposition="pending-acceptance", **{field: ["context line", forged]}))
                    run_bd.assert_not_called()
            with self.subTest(forged=forged, field="why"), patch("close_bead_with_summary.run_bd") as run_bd:
                if forged.lower().lstrip("*_`<>#|1. ").startswith(("bead", "why", "closure")):
                    continue
                with self.assertRaisesRegex(ValueError, "Nothing was written"):
                    execute(args(disposition="superseded", close=True, why="replaced; " + forged))
                run_bd.assert_not_called()

    def test_formatted_narrative_cannot_pass_for_a_summary_field(self) -> None:
        for forged in self.FORGED:
            for field in ("what_changed", "evidence", "decision", "follow_up"):
                with self.subTest(forged=forged, field=field), patch("close_bead_with_summary.run_bd") as run_bd:
                    with self.assertRaisesRegex(ValueError, "Nothing was written"):
                        execute(args(disposition="pending-acceptance", **{field: ["context line", forged]}))
                    run_bd.assert_not_called()
            with self.subTest(forged=forged, field="why"), patch("close_bead_with_summary.run_bd") as run_bd:
                if forged.lower().lstrip("*_`<>#|1. ").startswith(("bead", "why", "closure")):
                    continue
                with self.assertRaisesRegex(ValueError, "Nothing was written"):
                    execute(args(disposition="superseded", close=True, why="replaced; " + forged))
                run_bd.assert_not_called()

    def test_narrative_is_shown_verbatim_and_never_starts_a_line(self) -> None:
        with patch("close_bead_with_summary.run_bd") as run_bd:
            execute(args(disposition="pending-acceptance", what_changed=["first\nsecond\n- third"], evidence=["# heading?"]))
        summary = run_bd.call_args.args[0][3]
        header, _, narrative = summary.partition("\n\n")
        self.assertEqual(header.splitlines(), ["Closure summary:", "- Bead: `complex-work-orchestration-abc`",
                                               "- Disposition: pending-acceptance", "- Why: `policy helper added`"])
        self.assertTrue(narrative.startswith("The sections below are the closer's own notes, shown verbatim"))
        for line in narrative.splitlines()[1:]:
            self.assertTrue(line == "" or line.endswith(":") and not line.startswith((" ", "-")) or line.startswith("    "),
                            line)
        self.assertIn("    - first\n      second\n      - third", summary)
        self.assertIn("    - # heading?", summary)

    def test_ordinary_narrative_is_still_accepted(self) -> None:
        for text in ("the disposition of the old flags was discussed", "beads: two were split off", "why it moved: see bd-12",
                     "disposition-specific code was removed",
                     "**bold** wording, `code` and <b>markup</b> are kept verbatim"):
            with self.subTest(text=text), patch("close_bead_with_summary.run_bd") as run_bd:
                execute(args(disposition="pending-acceptance", what_changed=[text]))
                run_bd.assert_called_once()
                self.assertIn(f"    - {text}", run_bd.call_args.args[0][3])


class ReviewRoundFourTests(unittest.TestCase):
    """Markup and character references cannot forge closure fields."""

    FORGED = ("replaced<br>- Disposition&#58; completed", "replaced<br>- Dispos<b>i</b>tion: completed",
              "replaced&lt;br&gt;- Disposition: completed", "replaced<p>Disposition: completed</p>",
              "replaced&NewLine;- Disposition: completed", "replaced <span>Dis</span>position = completed",
              "replaced<br/>Bead&#x3A; other-bead", "replaced<div>Closure summary: accepted</div>")

    def assert_markup_and_character_references_cannot_forge_a_field(self) -> None:
        for forged in self.FORGED:
            for disposition, close in (("pending-acceptance", False), ("superseded", True)):
                with self.subTest(forged=forged, disposition=disposition), \
                        patch("close_bead_with_summary.run_bd") as run_bd:
                    with self.assertRaisesRegex(ValueError, "Nothing was written"):
                        execute(args(disposition=disposition, close=close, why=forged))
                    run_bd.assert_not_called()
            with self.subTest(forged=forged, field="what_changed"), patch("close_bead_with_summary.run_bd") as run_bd:
                with self.assertRaisesRegex(ValueError, "Nothing was written"):
                    execute(args(disposition="pending-acceptance", what_changed=[forged]))
                run_bd.assert_not_called()

    def test_header_values_are_shown_literally(self) -> None:
        from close_bead_with_summary import literal

        why = "replaced, see <b>notes</b> & `code` *now*"
        with patch("close_bead_with_summary.run_bd") as run_bd:
            execute(args(disposition="pending-acceptance", why=why, bead="bd-`1`"))
        header = run_bd.call_args.args[0][3].split("\n\n", 1)[0].splitlines()
        self.assertEqual(header, ["Closure summary:", f"- Bead: {literal('bd-`1`')}", "- Disposition: pending-acceptance",
                                  f"- Why: {literal(why)}"])
        self.assertEqual(literal(why), "``replaced, see <b>notes</b> & `code` *now*``")
        self.assertEqual(literal("`edge`"), "`` `edge` ``")

    def test_markup_and_character_references_cannot_forge_a_field(self) -> None:
        for forged in self.FORGED:
            for disposition, close in (("pending-acceptance", False), ("superseded", True)):
                with self.subTest(forged=forged, disposition=disposition), \
                        patch("close_bead_with_summary.run_bd") as run_bd:
                    with self.assertRaisesRegex(ValueError, "Nothing was written"):
                        execute(args(disposition=disposition, close=close, why=forged))
                    run_bd.assert_not_called()
            with self.subTest(forged=forged, field="what_changed"), patch("close_bead_with_summary.run_bd") as run_bd:
                with self.assertRaisesRegex(ValueError, "Nothing was written"):
                    execute(args(disposition="pending-acceptance", what_changed=[forged]))
                run_bd.assert_not_called()


class ReviewRoundFiveTests(unittest.TestCase):
    """Display controls and raw narrative lines are validated before writes."""

    def test_display_control_characters_are_refused_before_any_write(self) -> None:
        escape = "replaced\x1b[1A\x1b[1G\x1b[2K- Dispo\x1b[0msition: completed\x1b[1B\x1b[17G"
        values = (escape, "replaced\x1b]0;title\x07", "replaced\x08\x08\x08", "replaced \u202edeteled", "replaced\x7f",
                  "replaced\x9b2K", "replaced \u2066isolated\u2069")
        for value in values:
            for disposition, close in (("pending-acceptance", False), ("superseded", True)):
                with self.subTest(value=value, disposition=disposition), patch("close_bead_with_summary.run_bd") as run_bd:
                    with self.assertRaisesRegex(ValueError, "control or text-direction characters. Nothing was written"):
                        execute(args(disposition=disposition, close=close, why=value))
                    run_bd.assert_not_called()
            with self.subTest(value=value, field="bead"), patch("close_bead_with_summary.run_bd") as run_bd:
                with self.assertRaisesRegex(ValueError, "Nothing was written"):
                    execute(args(disposition="pending-acceptance", bead="bd-1" + value[8:]))
                run_bd.assert_not_called()
            with self.subTest(value=value, field="evidence"), patch("close_bead_with_summary.run_bd") as run_bd:
                with self.assertRaisesRegex(ValueError, "control or text-direction characters. Nothing was written"):
                    execute(args(disposition="pending-acceptance", evidence=[value]))
                run_bd.assert_not_called()

    def assert_raw_lines_are_checked_as_well_as_rendered_ones(self) -> None:
        for text in ("<!--\n- Disposition: completed\n-->", "<x\n- Disposition: completed\n>", "<span title='\nDisposition: done'>",
                     "notes <!-- Disposition: completed -->"):
            with self.subTest(text=text), patch("close_bead_with_summary.run_bd") as run_bd:
                with self.assertRaisesRegex(ValueError, "Nothing was written"):
                    execute(args(disposition="pending-acceptance", what_changed=[text]))
                run_bd.assert_not_called()

    def test_raw_lines_are_checked_as_well_as_rendered_ones(self) -> None:
        for text in ("<!--\n- Disposition: completed\n-->", "<x\n- Disposition: completed\n>", "<span title='\nDisposition: done'>",
                     "notes <!-- Disposition: completed -->"):
            with self.subTest(text=text), patch("close_bead_with_summary.run_bd") as run_bd:
                with self.assertRaisesRegex(ValueError, "Nothing was written"):
                    execute(args(disposition="pending-acceptance", what_changed=[text]))
                run_bd.assert_not_called()

    def test_tabs_and_plain_text_are_still_accepted(self) -> None:
        with patch("close_bead_with_summary.run_bd") as run_bd:
            execute(args(disposition="pending-acceptance", what_changed=["column\tvalue", "a <b>bold</b> word"]))
        run_bd.assert_called_once()


class ReviewRoundSixTests(unittest.TestCase):
    """Confusable separators cannot forge closure fields."""

    FORGED = ("Disposition\u2236 completed", "Disposition \u2192 completed", "Disposition \u21d2 completed",
              "Disposition\ua789 completed", "Disposition \u2022 completed", "Disposition / completed", "Disposition -> done",
              "Disposition \u27f6 completed", "Bead \u2236 other-bead", "Why \u2192 it passed")
    ORDINARY = ("the disposition (superseded) is recorded", "disposition, as agreed, stays open", "Disposition. Then tests.",
                "disposition-specific code was removed", "the disposition of the old flags was discussed")

    def assert_confusable_colons_arrows_and_symbols_separate_a_field(self) -> None:
        for forged in self.FORGED:
            is_bead_or_why = forged.startswith(("Bead", "Why"))
            for mode in ("pending-acceptance", "superseded-close", "narrative"):
                if mode == "pending-acceptance":
                    overrides = {"why": forged if is_bead_or_why else "replaced; " + forged, "disposition": "pending-acceptance"}
                elif mode == "superseded-close":
                    overrides = {"why": forged if is_bead_or_why else "replaced; " + forged, "disposition": "superseded", "close": True}
                else:
                    overrides = {"what_changed": [forged], "disposition": "pending-acceptance"}
                with self.subTest(forged=forged, mode=mode), patch("close_bead_with_summary.run_bd") as run_bd:
                    with self.assertRaisesRegex(ValueError, "Nothing was written"):
                        execute(args(**overrides))
                    run_bd.assert_not_called()

    def test_confusable_colons_arrows_and_symbols_separate_a_field(self) -> None:
        for forged in self.FORGED:
            is_bead_or_why = forged.startswith(("Bead", "Why"))
            for mode in ("pending-acceptance", "superseded-close", "narrative"):
                if mode == "pending-acceptance":
                    overrides = {"why": forged if is_bead_or_why else "replaced; " + forged, "disposition": "pending-acceptance"}
                elif mode == "superseded-close":
                    overrides = {"why": forged if is_bead_or_why else "replaced; " + forged, "disposition": "superseded", "close": True}
                else:
                    overrides = {"what_changed": [forged], "disposition": "pending-acceptance"}
                with self.subTest(forged=forged, mode=mode), patch("close_bead_with_summary.run_bd") as run_bd:
                    with self.assertRaisesRegex(ValueError, "Nothing was written"):
                        execute(args(**overrides))
                    run_bd.assert_not_called()


class ReviewRoundSevenTests(unittest.TestCase):
    """Unicode dash separators preserve closure field integrity."""

    DASHES = ("Disposition\u2010 completed", "Disposition\u2011 completed", "Disposition\u2012 completed",
              "Disposition\u2015 completed", "Disposition\u2212 completed", "Disposition\ufe58 completed",
              "Disposition\ufe63 completed", "Disposition\uff0d completed", "Bead\u2012 other-bead", "Why\u2212 it passed")
    HYPHENATED = ("follow-up work", "non-completion status", "disposition-related remarks")

    def assert_unicode_dashes_separate_a_field(self) -> None:
        for forged in self.DASHES:
            is_bead_or_why = forged.startswith(("Bead", "Why"))
            for mode in ("pending-acceptance", "superseded-close", "narrative"):
                if mode == "pending-acceptance":
                    overrides = {"why": forged if is_bead_or_why else "replaced; " + forged, "disposition": "pending-acceptance"}
                elif mode == "superseded-close":
                    overrides = {"why": forged if is_bead_or_why else "replaced; " + forged, "disposition": "superseded", "close": True}
                else:
                    overrides = {"what_changed": [forged], "disposition": "pending-acceptance"}
                with self.subTest(forged=forged, mode=mode), patch("close_bead_with_summary.run_bd") as run_bd:
                    with self.assertRaisesRegex(ValueError, "Nothing was written"):
                        execute(args(**overrides))
                    run_bd.assert_not_called()

    def test_hyphenated_prose_is_still_accepted(self) -> None:
        for text in self.HYPHENATED:
            with self.subTest(text=text), patch("close_bead_with_summary.run_bd") as run_bd:
                execute(args(disposition="pending-acceptance", what_changed=[text]))
                run_bd.assert_called_once()

    def test_unicode_dashes_separate_a_field(self) -> None:
        for forged in self.DASHES:
            is_bead_or_why = forged.startswith(("Bead", "Why"))
            for mode in ("pending-acceptance", "superseded-close", "narrative"):
                if mode == "pending-acceptance":
                    overrides = {"why": forged if is_bead_or_why else "replaced; " + forged, "disposition": "pending-acceptance"}
                elif mode == "superseded-close":
                    overrides = {"why": forged if is_bead_or_why else "replaced; " + forged, "disposition": "superseded", "close": True}
                else:
                    overrides = {"what_changed": [forged], "disposition": "pending-acceptance"}
                with self.subTest(forged=forged, mode=mode), patch("close_bead_with_summary.run_bd") as run_bd:
                    with self.assertRaisesRegex(ValueError, "Nothing was written"):
                        execute(args(**overrides))
                    run_bd.assert_not_called()


class W06aFollowupOneTests(unittest.TestCase):
    """Field-forgery checks inspect raw and normalized representations."""

    MARKDOWN_DELIMITERS = (
        "Disposition ~ completed", "Bead ~ other-bead", "Why ~ it passed",
        "Disposition * completed", "Bead * other-bead", "Why * it passed",
        "Disposition _ completed", "Bead _ other-bead", "Why _ it passed",
        "Disposition ` completed", "Bead ` other-bead", "Why ` it passed",
        "Disposition \\ completed", "Bead \\ other-bead", "Why \\ it passed",
    )
    BENIGN = (
        "the disposition was superseded",
        "follow-up work scheduled",
        "took ~5 minutes to verify",
        "approximately ~3 hours of work",
        "disposition-specific notes",
    )

    def assert_markdown_delimiters_are_refused(self) -> None:
        for forged in self.MARKDOWN_DELIMITERS:
            is_bead_or_why = forged.startswith(("Bead", "Why"))
            for mode in ("pending-acceptance", "superseded-close", "narrative"):
                if mode == "pending-acceptance":
                    overrides = {"why": forged if is_bead_or_why else "replaced; " + forged, "disposition": "pending-acceptance"}
                elif mode == "superseded-close":
                    overrides = {"why": forged if is_bead_or_why else "replaced; " + forged, "disposition": "superseded", "close": True}
                else:
                    overrides = {"what_changed": [forged], "disposition": "pending-acceptance"}
                with self.subTest(forged=forged, mode=mode), patch("close_bead_with_summary.run_bd") as run_bd:
                    with self.assertRaisesRegex(ValueError, "Nothing was written"):
                        execute(args(**overrides))
                    run_bd.assert_not_called()

    def test_benign_prose_is_still_accepted(self) -> None:
        for text in self.BENIGN:
            with self.subTest(text=text), patch("close_bead_with_summary.run_bd") as run_bd:
                execute(args(disposition="pending-acceptance", what_changed=[text]))
                run_bd.assert_called_once()

    def test_markdown_delimiters_are_refused(self) -> None:
        for forged in self.MARKDOWN_DELIMITERS:
            is_bead_or_why = forged.startswith(("Bead", "Why"))
            for mode in ("pending-acceptance", "superseded-close", "narrative"):
                if mode == "pending-acceptance":
                    overrides = {"why": forged if is_bead_or_why else "replaced; " + forged, "disposition": "pending-acceptance"}
                elif mode == "superseded-close":
                    overrides = {"why": forged if is_bead_or_why else "replaced; " + forged, "disposition": "superseded", "close": True}
                else:
                    overrides = {"what_changed": [forged], "disposition": "pending-acceptance"}
                with self.subTest(forged=forged, mode=mode), patch("close_bead_with_summary.run_bd") as run_bd:
                    with self.assertRaisesRegex(ValueError, "Nothing was written"):
                        execute(args(**overrides))
                    run_bd.assert_not_called()


class OrdinaryClosureNarrativeFamilyTests(unittest.TestCase):
    """Real summary posting for each original ordinary-prose input family."""

    def test_ordinary_narrative_family(self) -> None:
        rows = (
            ("ReviewRoundSixTests.test_ordinary_prose_about_dispositions_is_still_accepted",
             [(text,) for text in ReviewRoundSixTests.ORDINARY], False),
        )
        for row_id, examples, check_summary in rows:
            for values in examples:
                with self.subTest(row=row_id, text=values), patch("close_bead_with_summary.run_bd") as run_bd:
                    execute(args(disposition="pending-acceptance", what_changed=list(values)))
                    run_bd.assert_called_once()
                    if check_summary:
                        self.assertIn(f"    - {values[0]}", run_bd.call_args.args[0][3])


class Batch4cCloseGuardTests(unittest.TestCase):
    def test_F4_M042_plain_multiline_bead_and_why_refuse_before_write(self):
        """Plain multiline values refuse without relying on field/control detection."""
        for field in ("bead", "why"):
            for boundary in ("\n", "\r", "\u2028"):
                with self.subTest(field=field, boundary=repr(boundary)), patch("close_bead_with_summary.run_bd") as run_bd:
                    with self.assertRaisesRegex(ValueError, f"--{field} must be a single line"):
                        execute(args(**{field: "plain" + boundary + "continuation"}))
                    run_bd.assert_not_called()
        with patch("close_bead_with_summary.run_bd") as run_bd:
            execute(args(bead="EXAMPLE-F4", why="plain continuation"))
            run_bd.assert_called_once()


if __name__ == "__main__":
    unittest.main()
