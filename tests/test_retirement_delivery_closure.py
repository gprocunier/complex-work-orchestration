"""Real offline observations of a deterministic EXAMPLE recreator."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import close_bead_with_summary as closure  # noqa: E402
import prepare_artifact_acceptance as artifacts  # noqa: E402
import prepare_combined_review_binding as combined  # noqa: E402
import prepare_delivery_closure as offline  # noqa: E402
import prepare_validator_receipts as validators  # noqa: E402
from cwo_core import beads, candidate_identity as ci, checked_command as cc  # noqa: E402
from cwo_core import requirement_baseline as rb, workspace_capture  # noqa: E402
from tests import test_validator_receipt_preparation as fixtures  # noqa: E402

RESOURCE = "src/EXAMPLE-retired.txt"
SERVICE = "src/EXAMPLE-recreator.json"
RETIRED_BYTES = b"EXAMPLE retired resource\n"
EXPECTED_EVENT = b"EXAMPLE event active=False resource_present=False\n"

# This is an executable fake service event, not an accepting receipt/validator stub.
# It copies the candidate's service/resource state into a fresh temporary root,
# performs the next recreator event there, and measures its actual effect.
EVENT_SOURCE = '''from pathlib import Path
import json
import shutil
import tempfile

with tempfile.TemporaryDirectory(prefix="EXAMPLE-retirement-event-") as temporary:
    probe = Path(temporary)
    service = Path("src/EXAMPLE-recreator.json")
    resource = Path("src/EXAMPLE-retired.txt")
    if service.exists():
        shutil.copyfile(service, probe / "EXAMPLE-recreator.json")
    if resource.exists():
        shutil.copyfile(resource, probe / "EXAMPLE-retired.txt")
    state = probe / "EXAMPLE-recreator.json"
    active = json.loads(state.read_text())["active"] if state.exists() else False
    retired = probe / "EXAMPLE-retired.txt"
    if active:
        retired.write_bytes(b"EXAMPLE retired resource\\n")
    present = retired.exists()
    print(f"EXAMPLE event active={active} resource_present={present}", flush=True)
    if active or present:
        raise SystemExit(7)
'''


class RetirementDeliveryClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.effects = contextlib.ExitStack()
        self.addCleanup(self.effects.close)
        self.writers = [self.effects.enter_context(patch.object(
            module, name, side_effect=AssertionError("EXAMPLE forbidden production write")))
            for module, name in ((beads, "run_bd"), (beads, "run_bd_structured"),
                                 (closure, "run_bd"), (closure, "execute"))]

    def tearDown(self) -> None:
        for writer in self.writers:
            writer.assert_not_called()

    def begin(self, *, service="active", remove_resource=True) -> None:
        self.workspace = fixtures.TempGit(self)
        self.repo = self.workspace.root
        (self.repo / SERVICE).write_text('{"active":true}\n', encoding="utf-8")
        (self.repo / RESOURCE).write_bytes(RETIRED_BYTES)
        self.workspace.git("add", "-A")
        self.workspace.git("commit", "-q", "-m", "EXAMPLE active recreator before retirement")
        self.base = self.workspace.git("rev-parse", "HEAD")
        command = fixtures.spec(self.repo, "EXAMPLE-next-recreator-event", EVENT_SOURCE)
        absence = fixtures.criterion("EXAMPLE-retired-absent", artifacts.PREFIX + json.dumps({
            "op": "path-absent", "path": RESOURCE}), "artifact")
        absence["requirement"] = "EXAMPLE retirement removes the retired resource."
        absence["reference"] = "EXAMPLE-contract/retirement#resource-absent"
        event = fixtures.validator("EXAMPLE-recreator-disabled", command, EXPECTED_EVENT)
        event["requirement"] = (
            "EXAMPLE retirement disables or removes the recreator; its next event leaves the resource absent.")
        event["reference"] = "EXAMPLE-contract/retirement#recreator-disabled"
        self.initial = {
            "record_type": rb.BASELINE_RECORD_TYPE, "version": 1, "bead_id": "EXAMPLE-retirement",
            "baseline_version": 1, "criteria": [absence, event],
        }
        # Freeze the authority/expectations before candidate mutation, execution or results.
        self.declared = json.dumps(self.initial, sort_keys=True).encode()
        self.contract = self.repo.parent / "EXAMPLE-authoritative-baseline.json"
        self.contract.write_bytes(self.declared)
        self.chain = rb.resolve_chain(self.initial, [])
        self.bead = {"id": "EXAMPLE-retirement", "status": "open", "comments": [{
            "text": rb.reference_line(self.chain["bead_id"], 1, self.chain["digest"])}]}
        self.commands = {event["id"]: command}
        if remove_resource:
            (self.repo / RESOURCE).unlink()
        if service == "disabled":
            (self.repo / SERVICE).write_text('{"active":false}\n', encoding="utf-8")
        elif service == "removed":
            (self.repo / SERVICE).unlink()
        else:
            self.assertEqual(service, "active")
        self.candidate = ci.capture_candidate(
            self.repo, chain=self.chain, base_commit=self.base, scope_paths=["src"])
        self.bead["comments"].append({"text": ci.candidate_reference_line(
            self.chain["bead_id"], ci.candidate_digest(self.candidate))})
        self.target = offline.MemoryClosureTarget(self.bead)

    def observe(self, **changes):
        arguments = {"root": str(self.repo), "initial": self.initial, "candidate": self.candidate,
                     "bead": self.bead, "commands": self.commands}
        arguments.update(changes)
        observation = offline.observe_mixed(**arguments)
        self.assertEqual(self.contract.read_bytes(), self.declared)
        self.assertEqual(json.dumps(self.initial, sort_keys=True).encode(), self.declared)
        self.held(observation.report)
        return observation

    def review(self, observation):
        context = {"review_id": "EXAMPLE-retirement-review", "reviewer": "EXAMPLE fixture reviewer",
                   "verdict": "APPROVE", "snapshot": observation.combined["snapshot"] or {}}
        raw = json.dumps({"record_type": combined.REVIEW_TYPE, "version": 1, "context": context,
                          "findings": [], "summary": "EXAMPLE fixture approval; independence unauthenticated."}).encode()
        expected = {"record_type": combined.EXPECTATION_TYPE, "version": 1,
                    "context": copy.deepcopy(context),
                    "raw_review_sha256": "sha256:" + hashlib.sha256(raw).hexdigest()}
        return raw, expected

    def held(self, report) -> None:
        for field in offline.AUTHORITY_FIELDS:
            if field in report:
                self.assertIs(report[field], False)

    def unchanged(self) -> None:
        state = self.target.snapshot()
        self.assertEqual((state["comment_writes"], state["close_writes"], state["revision"]), (0, 0, 0))
        self.assertFalse(state["closed"])
        self.assertEqual(state["bead"], self.bead)
        self.assertFalse((self.repo / ".beads").exists())
        self.assertFalse((self.repo / ".orchestration-audit").exists())

    def close(self, bound):
        report = offline.close_offline(
            bound, self.target, operation_id="EXAMPLE-retirement-close", expected_revision=0)
        self.held(report)
        return report

    def reject(self, observation) -> None:
        self.assertFalse(observation.combined["combined_observations_complete"])
        with self.assertRaises(offline.ClosureError):
            offline.bind_review(observation, *self.review(observation))
        # No BoundReview can be issued. The final consumer also refuses absent bindings.
        refused = self.close(None)
        self.assertEqual(refused["state"], "REFUSED")
        self.assertFalse(refused["fake_completed"])
        self.assertTrue(refused["errors"])
        self.unchanged()

    def test_active_recreator_restores_removed_resource_and_blocks_completion(self) -> None:
        self.begin()
        with patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run, \
                patch.object(workspace_capture, "capture", wraps=workspace_capture.capture) as capture:
            observation = self.observe()
        run.assert_called_once()
        self.assertGreater(capture.call_count, 0)
        production = observation.production
        receipt = production["validator_evidence"][0]["result"]
        self.assertTrue(receipt["execution_started"])
        self.assertEqual(receipt["execution_status"], "failed")
        self.assertEqual(receipt["exit_code"], 7)
        self.assertEqual(receipt["failure_class"], "execution-failed")
        self.assertTrue(receipt["hash_match"])
        self.assertEqual(receipt["diagnostics"]["stdout"],
                         "EXAMPLE event active=True resource_present=True\n")
        self.assertEqual(set(receipt), validators.RESULT_FIELDS)
        artifact = production["artifact_diagnostic"]["criteria"][0]
        self.assertEqual(artifact["status"], "PASSED")
        self.assertFalse(production["validator_observations_complete"])
        self.assertNotEqual(production["consumer_diagnostic"]["criteria"][1]["state"], "OBSERVED_CONSISTENT")
        self.assertEqual(production["required_criterion_ids"], rb.required_criterion_ids(self.initial))
        self.assertEqual(production["validator_evidence"][0]["spec"], self.commands["EXAMPLE-recreator-disabled"])
        self.assertFalse((self.repo / RESOURCE).exists())
        self.assertTrue(json.loads((self.repo / SERVICE).read_text())["active"])
        self.reject(observation)

    def test_disabled_or_removed_recreator_allows_one_memory_only_completion(self) -> None:
        for service in ("disabled", "removed"):
            with self.subTest(service=service):
                self.begin(service=service)
                with patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run, \
                        patch.object(combined, "consume", wraps=combined.consume) as consume:
                    observation = self.observe()
                    bound = offline.bind_review(observation, *self.review(observation))
                    result = self.close(bound)
                run.assert_called_once()
                self.assertEqual(consume.call_count, 2)
                self.held(bound.report)
                self.assertTrue(observation.production["validator_observations_complete"])
                self.assertTrue(observation.combined["combined_observations_complete"])
                receipt = observation.production["validator_evidence"][0]["result"]
                self.assertEqual(receipt["diagnostics"]["stdout"].encode(), EXPECTED_EVENT)
                self.assertEqual(receipt["exit_code"], 0)
                self.assertEqual(observation.combined["snapshot"]["criterion_inventory"], self.initial["criteria"])
                self.assertTrue(result["fake_completed"], result["errors"])
                self.assertEqual((result["comment_writes"], result["close_writes"]), (1, 1))
                state = self.target.snapshot()
                self.assertEqual((state["revision"], state["comment_writes"], state["close_writes"]), (2, 1, 1))
                self.assertTrue(state["closed"])
                self.assertFalse((self.repo / ".beads").exists())
                self.assertFalse((self.repo / ".orchestration-audit").exists())

    def test_disabling_recreator_without_removing_resource_still_fails(self) -> None:
        self.begin(service="disabled", remove_resource=False)
        observation = self.observe()
        self.assertEqual(observation.production["artifact_diagnostic"]["criteria"][0]["status"], "FAILED")
        receipt = observation.production["validator_evidence"][0]["result"]
        self.assertEqual(receipt["exit_code"], 7)
        self.assertEqual(receipt["diagnostics"]["stdout"], "EXAMPLE event active=False resource_present=True\n")
        self.reject(observation)

    def test_omitting_named_recreator_requirement_or_command_cannot_complete(self) -> None:
        self.begin()
        omitted = copy.deepcopy(self.initial)
        omitted["criteria"].pop()
        for changes in ({"initial": omitted, "commands": {}}, {"commands": {}}):
            with self.subTest(omitted_baseline="initial" in changes):
                with patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run:
                    observation = self.observe(**changes)
                run.assert_not_called()
                self.assertTrue(observation.production["errors"])
                self.reject(observation)

    def test_post_review_reactivation_invalidates_original_binding_before_writes(self) -> None:
        self.begin(service="disabled")
        observation = self.observe()
        bound = offline.bind_review(observation, *self.review(observation))
        (self.repo / SERVICE).write_text('{"active":true}\n', encoding="utf-8")
        result = self.close(bound)
        self.assertEqual(result["state"], "REFUSED")
        self.assertFalse(result["fake_completed"])
        self.assertTrue(result["errors"])
        self.unchanged()
