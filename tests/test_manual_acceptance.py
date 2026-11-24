"""Manual delivery acceptance with a disposable candidate and Beads projection."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
import shutil
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import close_bead_with_summary as narrative  # noqa: E402
from cwo_core import candidate_identity as ci, host_records  # noqa: E402
from tests import test_candidate_identity as fixtures  # noqa: E402
from tests.real_beads_fixture import initialize_real_beads, run_fixture_subprocess  # noqa: E402


class ManualAcceptanceTests(fixtures.WorkspaceTestCase):
    def setUp(self):
        super().setUp()
        self.candidate = self.capture()
        self.digest = ci.candidate_digest(self.candidate)
        self.bead = fixtures.bead("proj-abc", self.baseline_lines[0],
                                  ci.candidate_reference_line("proj-abc", self.digest))
        self.baseline_path = self.tmp / "baseline.json"
        self.candidate_path = self.tmp / "candidate.json"
        self.baseline_path.write_text(json.dumps(self.baseline), encoding="utf-8")
        self.candidate_path.write_text(json.dumps(self.candidate), encoding="utf-8")
        self.inputs = ["--bead", "proj-abc", "--repo", str(self.repo),
                       "--baseline", str(self.baseline_path), "--candidate", str(self.candidate_path)]
        self.store = host_records.HostRecordStore.for_tests(self.tmp / "state")
        self.effects = []
        self.blockers = []
        self.children = []

    def bd(self, args):
        operation = args[0]
        if operation == "show":
            return json.dumps([self.bead])
        if operation == "dep":
            return json.dumps(self.blockers if "blocks" in args else self.children)
        self.effects.append(args)
        if operation == "comment":
            self.bead["comments"].append({"text": args[-1]})
        elif operation == "close":
            self.bead["status"] = "closed"
            self.bead["close_reason"] = args[args.index("--reason") + 1]
        else:
            self.fail(f"unexpected Beads operation {args}")
        return ""

    def deliver(self):
        args = narrative.parser().parse_args([
            *self.inputs, "--disposition", "pending-acceptance", "--why", "Ready for hand review"])
        from cwo_core import manual_delivery as manual
        with patch.object(manual, "project_beads", return_value=("fixture-database", self.bd)), \
                patch.object(manual, "delivery_session", return_value="delivery-process"), \
                host_records.using_test_store(self.store):
            narrative.execute(args)

    def accept(self, *, who=("uid:1000", ("reviewer-process",)), digest=None):
        from cwo_core import manual_delivery as manual
        import accept_delivery
        stdout, stderr = StringIO(), StringIO()
        args = [*self.inputs, "--reviewed-candidate", digest or self.digest,
                "--note", "Reviewed the changed paths and acceptance criteria.", "--json"]
        with patch.object(manual, "project_beads", return_value=("fixture-database", self.bd)), \
                patch.object(manual, "reviewer_session", return_value=who), \
                host_records.using_test_store(self.store), redirect_stdout(stdout), redirect_stderr(stderr):
            code = accept_delivery.main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_accept_and_close_records_review_and_closure_on_the_host_chain(self):
        self.deliver()
        self.assertEqual(self.bead["status"], "in_progress")
        code, output, errors = self.accept()
        self.assertEqual(code, 0, errors)
        self.assertTrue(json.loads(output)["closed"])
        self.assertEqual(self.bead["status"], "closed")
        self.assertEqual([args[0] for args in self.effects], ["comment", "close"])
        delivery, acceptance, closure = self.store.audit_events()
        self.assertEqual(delivery["event_type"], "manual_delivery_recorded")
        self.assertEqual(acceptance["event_type"], "manual_delivery_accepted")
        self.assertEqual(acceptance["manual_reviewer"], "uid:1000")
        self.assertEqual(acceptance["manual_review_note"], "Reviewed the changed paths and acceptance criteria.")
        self.assertEqual(acceptance["candidate_sha256"], self.digest)
        self.assertEqual(acceptance["baseline_sha256"], self.chain["digest"])
        self.assertTrue(acceptance["timestamp"])
        self.assertEqual(closure["event_type"], "manual_delivery_closed")
        self.assertEqual(closure["previous_event_hash"], acceptance["event_hash"])

    def assert_refused(self, expected, **kwargs):
        before = self.store.audit_events()
        code, _output, errors = self.accept(**kwargs)
        self.assertNotEqual(code, 0)
        self.assertIn(expected, errors)
        self.assertEqual(self.bead["status"], "in_progress")
        self.assertEqual([args[0] for args in self.effects], ["comment"])
        self.assertEqual(self.store.audit_events(), before)

    def test_delivering_session_cannot_accept_with_a_different_actor_name(self):
        self.deliver()
        self.assert_refused("delivering session", who=("uid:9999", ("child", "delivery-process")))

    def test_changed_candidate_is_refused(self):
        self.deliver()
        (self.repo / "src" / "tool.py").write_text("changed after review\n", encoding="utf-8")
        self.assert_refused("candidate")

    def test_reviewed_digest_is_checked_even_when_the_current_files_match(self):
        self.deliver()
        self.assert_refused("reviewed candidate", digest="sha256:" + "f" * 64)

    def test_changed_baseline_is_refused(self):
        self.deliver()
        self.bead["comments"].append({"text": self.baseline_lines[1]})
        self.assert_refused("baseline")

    def test_open_blocker_is_refused(self):
        self.deliver()
        self.blockers.append({"id": "proj-blocker", "status": "open", "dependency_type": "blocks"})
        self.assert_refused("blocker")

    def test_open_child_is_refused(self):
        self.deliver()
        self.children.append({"id": "proj-child", "status": "open", "dependency_type": "parent-child"})
        self.assert_refused("child")

    def test_a_newer_failed_comment_keeps_the_last_posted_delivery_current(self):
        self.deliver()
        original = self.store.audit_events()[0]
        with patch.object(self, "bd", side_effect=lambda args: (
                json.dumps([self.bead]) if args[0] == "show" else self.fail_comment())):
            with self.assertRaisesRegex(SystemExit, "timed out"):
                self.deliver()
        self.assertEqual(len(self.store.audit_events()), 2)
        code, _output, errors = self.accept()
        self.assertEqual(code, 0, errors)
        self.assertEqual(self.store.audit_events()[2]["manual_delivery_event"], original["event_hash"])

    def fail_comment(self):
        raise SystemExit("fixture comment timed out")

    def test_timeout_retry_never_reissues_close_and_can_confirm_a_late_write(self):
        self.deliver()
        close_calls = []
        bd = self.bd

        def time_out(args):
            if args[0] == "close":
                close_calls.append(args)
                raise SystemExit("fixture close timed out")
            return bd(args)

        with patch.object(self, "bd", side_effect=time_out):
            for _ in range(2):
                code, _output, errors = self.accept()
                self.assertEqual(code, 1)
                self.assertIn("closure is unconfirmed", errors)
        self.assertEqual(len(close_calls), 1)
        self.assertEqual([event["event_type"] for event in self.store.audit_events()],
                         ["manual_delivery_recorded", "manual_delivery_accepted"])
        bd(close_calls[0])
        (self.repo / "src" / "tool.py").write_text("changed after the close\n", encoding="utf-8")
        code, output, errors = self.accept()
        self.assertEqual(code, 0, errors)
        self.assertTrue(json.loads(output)["closed"])
        self.assertEqual(len(self.store.audit_events()), 3)

    def test_readback_confirms_close_when_the_subprocess_lost_its_acknowledgment(self):
        self.deliver()
        bd = self.bd

        def lost_ack(args):
            result = bd(args)
            if args[0] == "close":
                raise SystemExit("fixture acknowledgment timed out")
            return result

        with patch.object(self, "bd", side_effect=lost_ack):
            code, _output, errors = self.accept()
        self.assertEqual(code, 0, errors)
        self.assertEqual([args[0] for args in self.effects], ["comment", "close"])
        self.assertEqual(self.store.audit_events()[-1]["event_type"], "manual_delivery_closed")

    def test_foreground_shell_separation_refuses_known_agent_ancestry(self):
        from cwo_core import manual_delivery as manual
        with patch.object(manual.sys.stdin, "isatty", return_value=True), \
                patch.object(manual.os, "tcgetpgrp", return_value=42), \
                patch.object(manual.os, "getpgrp", return_value=42), \
                patch.object(manual, "_process_chain", return_value=(("shell", False), ("codex", True))):
            with self.assertRaisesRegex(ValueError, "agent session"):
                manual.reviewer_session()
        with patch.object(manual.sys.stdin, "isatty", return_value=True), \
                patch.object(manual.os, "tcgetpgrp", return_value=42), \
                patch.object(manual.os, "getpgrp", return_value=42), \
                patch.object(manual, "_process_chain", return_value=(("launching-shell", False),)):
            self.assertEqual(manual.reviewer_session(), (f"uid:{os.getuid()}", ("launching-shell",)))
        with patch.object(manual.sys.stdin, "isatty", return_value=False):
            with self.assertRaisesRegex(ValueError, "foreground terminal"):
                manual.reviewer_session()

    @unittest.skipUnless(shutil.which("bd"), "bd CLI not available")
    def test_project_beads_from_outside_checkout_and_explicit_beads_dir(self):
        from cwo_core import manual_delivery as manual
        env = {key: val for key, val in os.environ.items()
               if not key.startswith(("BEADS_", "BD_", "DOLT_", "GIT_"))}
        env["CWO_BEADS_TIMEOUT_SECONDS"] = "20"
        outside = self.tmp / "installed-package"
        outside.mkdir()
        other = self.tmp / "other-project"
        other.mkdir()
        fixtures.git(other, "init", "-q")
        for root, prefix in ((self.repo, "proj"), (other, "other")):
            initialize_real_beads(
                ["bd", "init", "--non-interactive", "--skip-agents", "--skip-hooks", "-p", prefix],
                cwd=root, env=env, check=True, capture_output=True)
            run_fixture_subprocess(["bd", "create", f"{prefix} task", "--id", f"{prefix}-abc", "--silent"],
                                   cwd=root, env=env, check=True, capture_output=True)
        with patch.object(manual.beads, "REPO_ROOT", outside), patch.dict(os.environ, env, clear=True):
            project_id, project = manual.project_beads(self.repo)
            self.assertEqual(json.loads(project(["show", "--json", "--", "proj-abc"]))[0]["title"], "proj task")
            with patch.dict(os.environ, {"BEADS_DIR": str(other / ".beads")}):
                other_id, redirected = manual.project_beads(self.repo)
                self.assertNotEqual(project_id, other_id)
                self.assertEqual(json.loads(redirected(["show", "--json", "--", "other-abc"]))[0]["title"],
                                 "other task")

    @unittest.skipUnless(shutil.which("bd"), "bd CLI not available")
    def test_installed_style_command_records_and_closes_disposable_bead(self):
        from cwo_core import manual_delivery as manual
        import accept_delivery
        env = {key: val for key, val in os.environ.items()
               if not key.startswith(("BEADS_", "BD_", "DOLT_", "GIT_"))}
        env["CWO_BEADS_TIMEOUT_SECONDS"] = "20"
        initialize_real_beads(
            ["bd", "init", "--non-interactive", "--skip-agents", "--skip-hooks", "-p", "proj"],
            cwd=self.repo, env=env, check=True, capture_output=True)
        candidate = self.capture()
        digest = ci.candidate_digest(candidate)
        self.candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        outside = self.tmp / "installed-package"
        outside.mkdir()
        with patch.object(manual.beads, "REPO_ROOT", outside), patch.dict(os.environ, env, clear=True), \
                host_records.using_test_store(self.store):
            _identity, run_bd = manual.project_beads(self.repo)
            run_bd(["create", "fixture delivery", "--id", "proj-abc", "--silent"])
            for reference in (self.baseline_lines[0], ci.candidate_reference_line("proj-abc", digest)):
                run_bd(["comment", "--", "proj-abc", reference])
            delivery_args = [*self.inputs, "--disposition", "pending-acceptance", "--why", "Ready for hand review"]
            with patch.object(manual, "delivery_session", return_value="delivery-process"):
                narrative.execute(narrative.parser().parse_args(delivery_args))
            with patch.object(manual, "reviewer_session", return_value=("uid:1000", ("reviewer-process",))), \
                    redirect_stdout(StringIO()), redirect_stderr(StringIO()) as errors:
                code = accept_delivery.main([*self.inputs, "--reviewed-candidate", digest, "--note", "Checked."])
            self.assertEqual(code, 0, errors.getvalue())
            result = json.loads(run_bd(["show", "--json", "--", "proj-abc"]))[0]
            self.assertEqual(result["status"], "closed")
            self.assertEqual(self.store.audit_events()[-1]["event_type"], "manual_delivery_closed")
