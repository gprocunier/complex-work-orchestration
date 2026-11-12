"""Literal authoritative requirements through memory-only closure."""
from __future__ import annotations

import contextlib
import copy
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
import produce_validator_evidence as producer  # noqa: E402
from cwo_core import beads, candidate_identity as ci, checked_command as cc  # noqa: E402
from cwo_core import requirement_baseline as rb, stage_completion  # noqa: E402
from cwo_core import typed_artifact_requirement as typed_requirement  # noqa: E402
from tests import test_validator_receipt_preparation as fixtures  # noqa: E402

REFERENCE = ROOT / "tests/fixtures/EXAMPLE-authoritative-artifact-requirement.json"
REQUIRED = b"EXAMPLE required output\n"
CONFLICTING = b"EXAMPLE conflicting output\n"


class AuthoritativeArtifactRequirementTests(unittest.TestCase):
    def setUp(self):
        self.effects = contextlib.ExitStack()
        self.addCleanup(self.effects.close)
        self.boundaries = []
        for module, name in ((beads, "run_bd"), (beads, "run_bd_structured"),
                             (closure, "run_bd"), (closure, "execute"), (stage_completion, "consume")):
            self.boundaries.append(self.effects.enter_context(patch.object(
                module, name, side_effect=AssertionError("EXAMPLE real effects remain held"))))

    def tearDown(self):
        for boundary in self.boundaries:
            boundary.assert_not_called()
        self.assertEqual(REFERENCE.read_bytes(), self.reference_bytes)

    def begin(self, *, conflicting=False, content=None, additive=False, requirement=None, route="artifact"):
        # Read the independent literal reference and declare the full baseline BEFORE implementation.
        self.reference_bytes = REFERENCE.read_bytes()
        obligation = rb.load_record(self.reference_bytes.decode("utf-8"))
        self.workspace = fixtures.TempGit(self)
        self.repo = self.workspace.root
        self.command = fixtures.spec(self.repo, "EXAMPLE-unrelated-command", "print('EXAMPLE unrelated check')\n")
        self.commands = {"EXAMPLE-unrelated": self.command}
        self.route = route
        if conflicting:
            predicate = json.loads(obligation["expected_outcome"][len(artifacts.PREFIX):])
            predicate["sha256"] = fixtures.sha(CONFLICTING)
            obligation["expected_outcome"] = artifacts.PREFIX + json.dumps(predicate)
        if requirement is not None:
            obligation["requirement"] = requirement
        if route != "artifact":
            substitute = fixtures.spec(self.repo, "EXAMPLE-substitute-command", "print('EXAMPLE substitute pass')\n")
            self.commands[obligation["id"]] = substitute
            declared = fixtures.validator(obligation["id"], substitute, b"EXAMPLE substitute pass\n")
            obligation.update(evidence_kind="validator", expected_outcome=declared["expected_outcome"])
        self.initial = {
            "record_type": rb.BASELINE_RECORD_TYPE, "version": 1, "bead_id": "EXAMPLE-bead",
            "baseline_version": 1, "criteria": [obligation],
        }
        unrelated = fixtures.validator("EXAMPLE-unrelated", self.command, b"EXAMPLE unrelated check\n")
        self.amendments = []
        if route == "validator-mixed":
            self.initial["criteria"].append(fixtures.criterion("EXAMPLE-support", artifacts.PREFIX + json.dumps({
                "op": "regular-file-sha256", "path": "src/support.txt",
                "sha256": fixtures.sha(b"EXAMPLE supporting output\n")}), "artifact"))
        if additive:
            updated = copy.deepcopy(self.initial)
            updated["baseline_version"] = 2
            updated["criteria"].append(unrelated)
            self.amendments = [fixtures.amendment(self.initial, updated)]
        else:
            self.initial["criteria"].append(unrelated)
        self.chain = rb.resolve_chain(self.initial, self.amendments)
        self.bead = {"id": "EXAMPLE-bead", "status": "open", "title": "EXAMPLE typed output task",
                     "comments": [{"text": rb.reference_line("EXAMPLE-bead", entry["version"], entry["digest"])}
                                  for entry in self.chain["baselines"]]}
        delivered = (CONFLICTING if conflicting else REQUIRED) if content is None else content
        (self.repo / "src/item.txt").write_bytes(delivered)
        if route == "validator-mixed":
            (self.repo / "src/support.txt").write_bytes(b"EXAMPLE supporting output\n")
        self.candidate = ci.capture_candidate(
            self.repo, chain=self.chain, base_commit=self.workspace.base, scope_paths=["src"])
        self.bead["comments"].append({"text": ci.candidate_reference_line(
            "EXAMPLE-bead", ci.candidate_digest(self.candidate))})
        self.target = offline.MemoryClosureTarget(self.bead)

    def observe(self):
        observe = offline.observe if self.route == "validator-only" else offline.observe_mixed
        return observe(str(self.repo), self.initial, self.candidate, self.bead,
                       self.commands, amendments=self.amendments)

    def review(self, observation, findings=(), *, snapshot=None):
        context = {"review_id": "EXAMPLE-review", "reviewer": "EXAMPLE unauthenticated reviewer",
                   "verdict": "APPROVE", "snapshot": (observation.combined["snapshot"] or {}) if snapshot is None else snapshot}
        raw = json.dumps({"record_type": combined.REVIEW_TYPE, "version": 1, "context": context,
                          "findings": list(findings), "summary": "EXAMPLE fake review; no independence authority."}).encode()
        expected = {"record_type": combined.EXPECTATION_TYPE, "version": 1, "context": context,
                    "raw_review_sha256": "sha256:" + fixtures.sha(raw)}
        return raw, expected

    def close(self, bound):
        return offline.close_offline(bound, self.target, operation_id="EXAMPLE-operation", expected_revision=0)

    def held(self, report):
        for name in offline.AUTHORITY_FIELDS:
            if name in report:
                self.assertIs(report[name], False)
        for value in report.values():
            if type(value) is dict:
                self.held(value)
            elif type(value) is list:
                for item in value:
                    if type(item) is dict:
                        self.held(item)

    def empty(self):
        state = self.target.snapshot()
        self.assertEqual((state["comment_writes"], state["close_writes"], state["closed"]), (0, 0, False))
        self.assertFalse((self.repo / ".beads").exists())
        self.assertFalse((self.repo / ".orchestration-audit").exists())

    def test_conflicting_expected_value_never_completes(self):
        self.begin(conflicting=True)
        self.assertTrue(ci.check_candidate(self.candidate, root=self.repo, chain=self.chain, bead=self.bead)["valid"])
        with patch.object(producer, "produce_mixed", wraps=producer.produce_mixed) as produce, \
                patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run:
            actual = cc.execute_checked_command(self.command)
            observation = self.observe()
        produce.assert_called_once()
        self.assertGreaterEqual(run.call_count, 1)
        self.assertEqual((actual["execution_status"], actual["exit_code"]), ("passed", 0))
        # Even a real full receipt with correct baseline/candidate joins cannot make the combined gate pass.
        context = observation.context
        context["validator_evidence"] = [producer._wrapper(
            {"candidate": self.candidate, "commands": self.commands}, self.chain, "EXAMPLE-unrelated", actual)]
        diagnostic = combined.observe(context)
        raw, expected = self.review(observation)
        try:
            bound = offline.bind_review(observation, raw, expected)
        except offline.ClosureError:
            bound = observation  # An incomplete observation cannot be used as an issued final binding.
        result = self.close(bound)
        self.assertFalse(result["fake_completed"],
                         "EXAMPLE authoritative contradiction reached original memory completion with matching bindings")
        self.empty()
        self.assertEqual(observation.production["checked_command_calls"], 0)
        raw, expected = self.review(observation, snapshot=diagnostic["snapshot"])
        prepared = combined.prepare(context, raw, expected)
        self.assertFalse(prepared["combined_observations_complete"])
        self.assertEqual([entry["state"] for entry in diagnostic["snapshot"]["criteria"]],
                         ["UNASSESSABLE", "OBSERVED_CONSISTENT"])
        artifact = observation.production["artifact_diagnostic"]["criteria"][0]
        self.assertEqual(artifact["id"], "EXAMPLE-required-output")
        self.assertEqual(artifact["status"], "UNASSESSABLE")
        self.assertIn("contradicts the declared literal requirement", artifact["reason"])
        self.held(observation.report)
        self.held(result)

    def test_nearest_correct_expectation_completes_with_additive_continuity(self):
        self.begin(additive=True)
        with patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run, \
                patch.object(combined, "consume", wraps=combined.consume) as consume:
            observation = self.observe()
            resolved = {"id": "EXAMPLE-resolved", "blocking": True, "state": "RESOLVED", "text": "EXAMPLE resolved finding."}
            raw, expected = self.review(observation, [resolved])
            bound = offline.bind_review(observation, raw, expected)
            result = self.close(bound)
        run.assert_called_once()
        self.assertEqual(consume.call_count, 2)
        self.assertTrue(result["fake_completed"], result["errors"])
        self.assertTrue(observation.combined["combined_observations_complete"])
        snapshot = bound.prepared["snapshot"]
        self.assertEqual(snapshot["criterion_inventory"], self.chain["baseline"]["criteria"])
        self.assertEqual(observation.production["validator_evidence"][0]["baseline_digest"], self.chain["digest"])
        self.assertEqual(observation.production["artifact_diagnostic"]["criteria"][0]["observation"]["sha256"], fixtures.sha(REQUIRED))
        state = self.target.snapshot()
        self.assertEqual((state["comment_writes"], state["close_writes"], state["closed"]), (1, 1, True))
        self.held(result)

    def test_typed_requirement_cannot_be_routed_through_unrelated_validators(self):
        for route in ("validator-only", "validator-mixed"):
            for malformed in (False, True):
                with self.subTest(route=route, malformed=malformed):
                    requirement = typed_requirement.PREFIX + '{"path":"src/item.txt"}' if malformed else None
                    self.begin(content=CONFLICTING, route=route, requirement=requirement)
                    actual = {name: cc.execute_checked_command(command) for name, command in self.commands.items()}
                    self.assertTrue(all(result["execution_status"] == "passed" for result in actual.values()))
                    observation = self.observe()
                    raw, expected = self.review(observation)
                    try:
                        bound = offline.bind_review(observation, raw, expected)
                    except offline.ClosureError:
                        bound = observation
                    result = self.close(bound)
                    self.assertFalse(result["fake_completed"],
                                     "EXAMPLE typed literal requirement bypassed reconciliation via validator evidence")
                    self.empty()
                    self.assertEqual(observation.production["checked_command_calls"], 0)
                    context = observation.context
                    context["validator_evidence"] = [producer._wrapper(
                        {"candidate": self.candidate, "commands": self.commands}, self.chain, name, receipt)
                        for name, receipt in actual.items()]
                    diagnostic = combined.observe(context)
                    states = {entry["id"]: entry for entry in diagnostic["snapshot"]["criteria"]}
                    self.assertEqual(states["EXAMPLE-required-output"]["state"], "UNASSESSABLE")
                    self.assertIn("requires artifact evidence", states["EXAMPLE-required-output"]["reason"])
                    self.assertEqual(states["EXAMPLE-unrelated"]["state"], "OBSERVED_CONSISTENT")
                    self.assertFalse(diagnostic["combined_observations_complete"])
                    self.held(result)

    def test_correct_expectation_with_conflicting_implementation_still_fails(self):
        self.begin(content=CONFLICTING)
        observation = self.observe()
        self.assertTrue(observation.production["validator_observations_complete"])
        self.assertEqual(observation.production["artifact_diagnostic"]["criteria"][0]["status"], "FAILED")
        with self.assertRaises(offline.ClosureError):
            offline.bind_review(observation, *self.review(observation))
        self.empty()

    def test_complete_observation_cannot_ignore_open_blocking_finding(self):
        self.begin()
        observation = self.observe()
        self.assertTrue(observation.combined["combined_observations_complete"])
        blocker = {"id": "EXAMPLE-open", "blocking": True, "state": "OPEN", "text": "EXAMPLE unresolved finding."}
        with self.assertRaises(offline.ClosureError):
            offline.bind_review(observation, *self.review(observation, [blocker]))
        self.empty()

    def test_literal_path_and_operation_cannot_be_replaced_by_passing_predicate(self):
        for predicate in ({"op": "path-absent", "path": "src/item.txt"},
                          {"op": "regular-file-sha256", "path": "src/other.txt", "sha256": fixtures.sha(REQUIRED)}):
            with self.subTest(predicate=predicate):
                self.begin()
                changed = copy.deepcopy(self.initial)
                changed["criteria"][0]["expected_outcome"] = artifacts.PREFIX + json.dumps(predicate)
                # Rebinding hashes cannot reconcile the contrary predicate with its independent literal source.
                chain = rb.resolve_chain(changed)
                candidate = ci.capture_candidate(self.repo, chain=chain, base_commit=self.workspace.base, scope_paths=["src"])
                bead = copy.deepcopy(self.bead)
                bead["comments"] = [{"text": rb.reference_line("EXAMPLE-bead", 1, chain["digest"])},
                                    {"text": ci.candidate_reference_line("EXAMPLE-bead", ci.candidate_digest(candidate))}]
                report = artifacts.prepare(self.repo, changed, candidate, bead)
                self.assertEqual(report["criteria"][0]["status"], "UNASSESSABLE")
                self.assertIn("contradicts the declared literal requirement", report["criteria"][0]["reason"])
                self.empty()

    def test_plain_prose_remains_uninterpreted_and_utf8_literal_has_exact_bytes(self):
        self.begin(requirement="EXAMPLE prose still requires independent interpretation.")
        self.assertIsNone(typed_requirement.artifact_expectation(self.initial["criteria"][0]["requirement"]))
        literal = typed_requirement.PREFIX + json.dumps({"path": "src/item.txt", "utf8": "EXAMPLE café\n"})
        expected = typed_requirement.artifact_expectation(literal)
        self.assertEqual(expected["sha256"], fixtures.sha("EXAMPLE café\n".encode("utf-8")))
        observation = self.observe()
        self.assertTrue(self.close(offline.bind_review(observation, *self.review(observation)))["fake_completed"])

    def test_malformed_literal_requirements_remain_unassessable(self):
        malformed = (
            '{"path":"src/item.txt","utf8":"EXAMPLE","utf8":"EXAMPLE other"}',
            '{"path":"src/item.txt","utf8":7}',
            '{"path":"src/item.txt","utf8":"EXAMPLE","extra":true}',
            '{"path":"src/item.txt"}',
            '[]',
        )
        for payload in malformed:
            with self.subTest(payload=payload):
                self.begin(requirement=typed_requirement.PREFIX + payload)
                report = artifacts.prepare(self.repo, self.initial, self.candidate, self.bead)
                self.assertEqual(report["criteria"][0]["status"], "UNASSESSABLE")
                self.assertFalse(report["artifact_observations_complete"])
                self.empty()


    def test_escaped_duplicate_surrogate_key_has_structured_refusal(self):
        payload = r'{"path":"src/item.txt","utf8":"EXAMPLE","\ud800":0,"\ud800":1}'
        self.begin(requirement=typed_requirement.PREFIX + payload)
        report = artifacts.prepare(self.repo, self.initial, self.candidate, self.bead)
        self.assertEqual(report["criteria"][0]["status"], "UNASSESSABLE")
        self.assertFalse(report["artifact_observations_complete"])
        json.dumps(report, ensure_ascii=False).encode("utf-8")
        observation = self.observe()
        with self.assertRaises(offline.ClosureError):
            offline.bind_review(observation, *self.review(observation))
        self.assertFalse(self.close(observation)["fake_completed"])
        self.empty()


if __name__ == "__main__":
    unittest.main()
