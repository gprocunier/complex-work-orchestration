from __future__ import annotations

from contextlib import chdir
import json
import subprocess
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_contractor_packet
import dispatch_work
import generate_manual_dispatch_prompt
from cwo_core import audit, beads, util
from cwo_core.util import packet_payload_hash
from tests.outbound_approval_helpers import REFERENCE, approved_outbound, outbound_grant
from tests.test_policy_current_effects import current_policy, run_main


BEAD = "review-1"
EPIC = "epic-1"
EXECUTOR = "claude_code_manual"
ASSIGNMENT = {
    "id": BEAD,
    "parent": EPIC,
    "title": "Review the public retry plan.",
    "labels": ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"],
}


class OutboundApprovalTests(unittest.TestCase):
    def build(self, home, *extra, boundary="redacted-packet", dispatch="review-first", saved_bead=True):
        output = home / ((dispatch or "review-generated") + ".json")
        args = ["build_contractor_packet.py", "--bead", BEAD, "--executor", EXECUTOR,
                "--share-boundary", boundary, "--format", "json", "--output", str(output)]
        if saved_bead:
            bead = home / "bead.json"
            bead.write_text(json.dumps(ASSIGNMENT))
            args += ["--bead-json-file", str(bead)]
        if dispatch is not None:
            args += ["--dispatch-id", dispatch]
        spies, failure = run_main(build_contractor_packet, args + list(extra))
        return output, spies, failure

    def test_flags_and_editable_opt_in_json_cannot_build_a_production_packet(self):
        with current_policy() as home:
            editable = home / "permission.json"
            editable.write_text(json.dumps({"allowed": True, "executor": EXECUTOR, "bead_id": BEAD,
                                            "share_boundary": "redacted-packet"}))
            for args, reason in (
                (("--external-ok",), "protected --opt-in-record"),
                (("--opt-in-record", str(editable)), "protected --opt-in-record"),
                (("--no-audit", "--external-ok"), "allowed only with --rehearsal"),
            ):
                with self.subTest(args=args), mock.patch.dict("os.environ", {"CWO_LEAD_AUTHORITY_CONFIG": str(editable)}):
                    packet, spies, failure = self.build(home, *args)
                    self.assertIn(reason, str(failure))
                    self.assertFalse(packet.exists())
                    self.assertEqual(spies.total(), 0)
                    self.assertEqual(spies.stdout.getvalue(), "")

    def test_one_grant_covers_repeat_builds_and_exports(self):
        from tests.dispatch_workload_fixture import write_workload

        grant = outbound_grant(BEAD, EPIC, EXECUTOR, "repo-readonly")
        with current_policy() as home, approved_outbound(grant) as calls:
            for dispatch in (None, "review-second"):
                packet, _, failure = self.build(home, "--opt-in-record", REFERENCE, dispatch=dispatch)
                self.assertIsNone(failure)
                document = json.loads(packet.read_text())
                self.assertEqual(document["opt_in_basis"], "host-approval")
                if dispatch is None:
                    self.assertIn(".dispatch-review-1-", document["dispatch_id"])
                else:
                    self.assertEqual(document["dispatch_id"], dispatch)
                workload = write_workload(home / "workload.json", document)
                export = ["generate_manual_dispatch_prompt.py", "--packet", str(packet), "--workload", workload, "--json"]
                spies, failure = run_main(generate_manual_dispatch_prompt, export)
                self.assertIsNone(failure)
                self.assertIn("Review the public retry plan.", spies.stdout.getvalue())
                self.assertNotIn(REFERENCE, spies.stdout.getvalue())
            self.assertEqual(calls.call_args_list, [mock.call("outbound-approval", REFERENCE)] * 4)

    def test_one_skill_keeps_target_checkout_approvals_separate(self):
        from tests.dispatch_workload_fixture import write_workload

        with current_policy() as home:
            first, second = home / "first-project", home / "second-project"
            for project in (first, second):
                project.mkdir()
                subprocess.run(["git", "init", "-q"], cwd=project, check=True, capture_output=True)
            nested = first / "nested"
            nested.mkdir()
            grant = outbound_grant(BEAD, EPIC, EXECUTOR, project=first.resolve())
            command = ["bd", "show", "--json", "--", BEAD]
            completed = subprocess.CompletedProcess(command, 0, stdout=json.dumps(ASSIGNMENT), stderr="")
            wrong_git = {"GIT_DIR": str(second / ".git"), "GIT_WORK_TREE": str(second)}
            with approved_outbound(grant), chdir(nested):
                with mock.patch.dict("os.environ", wrong_git), mock.patch.object(beads, "require_bd"), \
                        mock.patch.object(beads.subprocess, "run", return_value=completed) as show:
                    packet, _, failure = self.build(first, "--opt-in-record", REFERENCE, saved_bead=False)
                self.assertIsNone(failure, str(failure))
                self.assertEqual(show.call_args.args, (command,))
                self.assertEqual(show.call_args.kwargs["cwd"], first.resolve())
                self.assertTrue(wrong_git.keys().isdisjoint(show.call_args.kwargs["env"]))
                workload = write_workload(home / "workload.json", json.loads(packet.read_text()))
                export = ["generate_manual_dispatch_prompt.py", "--packet", str(packet), "--workload", workload]
                spies, failure = run_main(generate_manual_dispatch_prompt, export)
                self.assertIsNone(failure, str(failure))
                self.assertIn("Review the public retry plan.", spies.stdout.getvalue())
            git_overrides = {"GIT_DIR": str(first / ".git"), "GIT_WORK_TREE": str(first)}
            with approved_outbound(grant), chdir(second), mock.patch.dict("os.environ", git_overrides):
                rejected, spies, failure = self.build(second, "--opt-in-record", REFERENCE)
                self.assertIn("does not match this project", str(failure))
                self.assertFalse(rejected.exists())
                self.assertEqual(spies.total(), 0)
                spies, failure = run_main(generate_manual_dispatch_prompt, export)
                self.assertIn("does not match this project", str(failure))
                self.assertEqual(spies.total(), 0)
                self.assertEqual(spies.stdout.getvalue(), "")

    def test_long_example_bead_uses_safe_generated_dispatch_id_for_production_export(self):
        from tests.dispatch_workload_fixture import write_workload

        bead_file = ROOT / "examples" / "sample-bead.json"
        bead_id = json.loads(bead_file.read_text())["id"]
        grant = outbound_grant(bead_id, EPIC, EXECUTOR, "redacted-packet")
        nonce = uuid.UUID("01234567-89ab-4cde-8fab-0123456789ab")
        with current_policy() as home, approved_outbound(grant):
            packet = home / "packet.json"
            argv = ["build_contractor_packet.py", "--bead", bead_id, "--bead-json-file", str(bead_file),
                    "--epic", EPIC, "--executor", EXECUTOR, "--share-boundary", "redacted-packet",
                    "--opt-in-record", REFERENCE, "--format", "json", "--output", str(packet)]
            with mock.patch.object(util, "uuid") as generator:
                generator.uuid4.return_value = nonce
                _, failure = run_main(build_contractor_packet, argv)
            self.assertIsNone(failure, str(failure))
            generator.uuid4.assert_called_once_with()
            self.assertEqual(json.loads(packet.read_text())["dispatch_id"], str(nonce))
            workload = write_workload(home / "workload.json", json.loads(packet.read_text()))
            export = ["generate_manual_dispatch_prompt.py", "--packet", str(packet), "--workload", workload]
            spies, failure = run_main(generate_manual_dispatch_prompt, export)
            self.assertIsNone(failure, str(failure))
            self.assertIn(f"Dispatch ID: {nonce}", spies.stdout.getvalue())
            self.assertIn(f"Assigned bead: {bead_id}", spies.stdout.getvalue())
            original = packet.read_bytes()
            explicit_id = f"{nonce}.dispatch-{bead_id}-20261127T120000Z"
            with mock.patch.object(util, "uuid") as generator:
                spies, failure = run_main(build_contractor_packet, argv + ["--dispatch-id", explicit_id])
            generator.uuid4.assert_not_called()
            self.assertIn("outbound screening refused contractor packet", str(failure))
            self.assertEqual(spies.total(), 0)
            self.assertEqual(packet.read_bytes(), original)

    def test_scope_mismatches_are_refused_before_artifacts_or_audit(self):
        grant = outbound_grant(BEAD, EPIC, EXECUTOR, "redacted-packet")
        cases = {"project": "/another/project", "bead_id": "review-other", "epic_id": None,
                 "executor": "gemini_manual_reviewer", "provider_key": "google_manual"}
        for field, value in cases.items():
            with self.subTest(field=field), current_policy() as home, approved_outbound({**grant, field: value}):
                packet, spies, failure = self.build(home, "--opt-in-record", REFERENCE)
                self.assertIn("does not match this project, assignment or destination", str(failure))
                self.assertFalse(packet.exists())
                self.assertEqual(spies.total(), 0)
        with current_policy() as home, approved_outbound(grant):
            packet, spies, failure = self.build(home, "--opt-in-record", REFERENCE, "--allow-disclosure-escalation",
                                               "--waiver-reason", "test boundary", boundary="repo-readonly")
            self.assertIn("does not permit this share boundary", str(failure))
            self.assertFalse(packet.exists())
            self.assertEqual(spies.total(), 0)

    def test_approved_build_still_screens_prepared_bytes_before_audit(self):
        grant = outbound_grant(BEAD, EPIC, EXECUTOR, "redacted-packet")
        with current_policy() as home, approved_outbound(grant):
            packet, spies, failure = self.build(home, "--opt-in-record", REFERENCE, "--snippet", "pin=4831")
            self.assertIn("outbound screening refused contractor packet", str(failure))
            self.assertFalse(packet.exists())
            self.assertEqual(spies.total(), 0)
            self.assertEqual(spies.stdout.getvalue(), "")

    def test_forged_packet_and_audit_pointer_need_current_host_approval(self):
        grant = outbound_grant(BEAD, EPIC, EXECUTOR, "redacted-packet")
        with current_policy() as home:
            with approved_outbound(grant):
                packet, _, failure = self.build(home, "--opt-in-record", REFERENCE)
                self.assertIsNone(failure)
            document = json.loads(packet.read_text())
            document["dispatch_id"] = "review-forged"
            document["packet_sha256"] = packet_payload_hash(document)
            packet.write_text(json.dumps(document))
            audit.record_audit_event({"event_type": "packet_built", "bead_id": BEAD,
                                      "dispatch_id": document["dispatch_id"],
                                      "packet_sha256": document["packet_sha256"],
                                      "operator_approval_ref": "f" * 64})
            with approved_outbound(grant):
                argv = ["dispatch_work.py", "--packet", str(packet)]
                spies, failure = run_main(dispatch_work, argv)
                self.assertIn("protected outbound approval is unavailable", str(failure))
                self.assertEqual(spies.total(), 0)
                self.assertEqual(spies.stdout.getvalue(), "")
                waiver = ["--allow-unlinked-packet", "--waiver-reason", "local fixture"]
                spies, failure = run_main(dispatch_work, argv + waiver)
                self.assertIn("only for a local rehearsal", str(failure))
                self.assertEqual(spies.total(), 0)
                spies, failure = run_main(dispatch_work, argv + waiver + ["--rehearsal", "--no-audit"])
                self.assertIsNone(failure)
                self.assertIn("Local rehearsal only.", spies.stdout.getvalue())
                self.assertEqual(spies.total(), 0)
