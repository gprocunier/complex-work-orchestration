"""Adjudication bound to recorded evidence, provenance derived from dispatch records.

The first class needs nothing beyond the long-standing helper signature, so it
also runs against the integration candidate before this change and shows the
defects there. The later classes use fake dispatch and adjudication records.
"""

from __future__ import annotations

import copy
import hashlib
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.synthesis import evaluate_synthesis_inputs  # noqa: E402

CANDIDATE = "commit:" + "a" * 40 + " tree:" + "b" * 40
OTHER_CANDIDATE = "commit:" + "c" * 40 + " tree:" + "d" * 40
SCOPE = "bead:cwo-w08-fixture"
RULE = "synthesis-input-adjudication"
TRIPWIRE = "return-tripwire:review-suppression"
PACKET_ONLY_GO = "reviewer packet-only GO claim for merge/readiness requires architect adjudication"
ROLE_LABELS = (
    {"architect_adjudicated": True},
    {"architect_upgrade": True},
    {"architect_adjudication_authorized": True},
    {"implementation_block_override_authorized": True},
    {"synthesis_use_authority": "architect"},
    {"synthesis_use_authority": "architect-adjudication"},
)


# Round 8: an unreadable dispatch_id may name any dispatch. On an input it may be
# another input's dispatch, and on a dispatch record it may be a second record
# for any dispatch, so no other attempted binding holds beside it.
WILDCARD_INPUT_REASON = "another input has no readable dispatch_id, so it may name this dispatch"
WILDCARD_RECORD_REASON = ("a dispatch record is not an object or has no readable dispatch_id, so it may be this "
                          "dispatch's record")


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def dispatch(dispatch_id: str, executor: str, *, candidate: str = CANDIDATE, **extra: object) -> dict:
    record = {
        "record_type": "cwo-dispatch-record",
        "version": 1,
        "dispatch_id": dispatch_id,
        "executor": executor,
        "return_sha256": sha("return:" + dispatch_id),
        "candidate": candidate,
    }
    record.update(extra)
    return record


def returned(lane: str, dispatch_id: str | None = None, **fields: object) -> dict:
    entry = {"lane": lane, "disposition": "accepted"}
    if dispatch_id is not None:
        entry["dispatch_id"] = dispatch_id
        entry["return_sha256"] = sha("return:" + dispatch_id)
    entry.update(fields)
    return entry


def tripwire_held(lane: str, dispatch_id: str | None = None, **fields: object) -> dict:
    held = {
        "recommended_synthesis_use": "primary",
        "implementation_blocked": True,
        "hold_classification": "return-tripwire",
        "hold_reasons": [TRIPWIRE],
    }
    held.update(fields)
    return returned(lane, dispatch_id, **held)


def adjudication(
    adjudication_id: str,
    dispatch_id: str,
    *,
    decision: str = "accepted",
    findings: tuple[str, ...] = (TRIPWIRE,),
    evidence: list[dict] | None = None,
    **overrides: object,
) -> dict:
    record = {
        "record_type": "cwo-return-adjudication",
        "version": 1,
        "adjudication_id": adjudication_id,
        "dispatch_id": dispatch_id,
        "return_sha256": sha("return:" + dispatch_id),
        "candidate": CANDIDATE,
        "scope": SCOPE,
        "finding_ids": list(findings),
        "decision": decision,
        "rationale": "checked the flagged clause against the repository; it does not apply here",
        "supporting_evidence": (
            evidence
            if evidence is not None
            else [
                {
                    "artifact": "validation/focused-tests.txt",
                    "artifact_type": "validation-log",
                    "sha256": sha("validation log for " + adjudication_id),
                    "finding_ids": list(findings),
                }
            ]
        ),
        "authority": {"rule": RULE, "reference": "policy/synthesis-policy.yaml#adjudication_authority"},
        "adjudicator": "lead-session-1",
    }
    record.update(overrides)
    return record


PEERS = [
    dispatch("d-opus", "claude_architecture_critic"),
    dispatch("d-chatgpt", "chatgpt_pro_browser_master_reviewer"),
]


def peer_inputs() -> list[dict]:
    return [returned("opus", "d-opus"), returned("chatgpt", "d-chatgpt")]


def run(inputs: list[dict], records: list[dict] | None = None, adjudications: list[dict] | None = None, **kwargs: object) -> dict:
    return evaluate_synthesis_inputs(
        inputs,
        dispatch_records=records,
        adjudications=adjudications,
        candidate=kwargs.pop("candidate", CANDIDATE),
        scope=kwargs.pop("scope", SCOPE),
        **kwargs,
    )


def lane(result: dict, name: str) -> dict:
    return next(item for item in result["input_summaries"] if item["lane"] == name)


class CallerClaimsGrantNothingTests(unittest.TestCase):
    """Negative regressions that use only the long-standing helper signature."""

    def test_role_label_restriction_family(self) -> None:
        rows = (
            ("test_role_labels_cannot_clear_a_tripwire_hold", tripwire_held("held"),
             [{"lane": "control", "provider_camp": "openai", "disposition": "accepted"}],
             "open-risk", "blocked", 1),
            ("test_role_labels_cannot_clear_a_packet_only_go_hold",
             {"lane": "master", "disposition": "accepted", "recommended_synthesis_use": "primary",
              "implementation_blocked": True, "hold_reasons": [PACKET_ONLY_GO]}, [], "open-risk", None, None),
            ("test_role_labels_cannot_clear_a_peer_review_hold",
             {"lane": "opus", "provider_camp": "anthropic", "disposition": "accepted",
              "recommended_synthesis_use": "primary", "implementation_blocked": True,
              "hold_reasons": ["peer-review-pending"]},
             [{"lane": "chatgpt", "provider_camp": "openai", "disposition": "accepted"}],
             "open-risk", "blocked", None),
            ("test_role_labels_cannot_upgrade_a_salvage_only_provider",
             {"lane": "gemini", "provider_camp": "google", "disposition": "accepted", "synthesis_use": "primary",
              "reason": "architect upgraded one evaluated finding"},
             [{"lane": "opus", "provider_camp": "anthropic", "disposition": "accepted"}],
             "salvage-only", "blocked", None),
            ("test_role_labels_cannot_promote_a_recommended_primary_return",
             {"lane": "opus", "disposition": "accepted", "recommended_synthesis_use": "primary"},
             [{"lane": "chatgpt", "disposition": "accepted"}], None, "blocked", None),
        )
        for row_id, entry, controls, expected_use, expected_status, expected_count in rows:
            for label in ROLE_LABELS:
                with self.subTest(row=row_id, label=label):
                    inputs = [{**copy.deepcopy(entry), **copy.deepcopy(label)}, *copy.deepcopy(controls)]
                    result = evaluate_synthesis_inputs(inputs)
                    summary = result["input_summaries"][0]
                    if expected_use is None:
                        self.assertNotEqual(summary["synthesis_use"], "primary")
                    else:
                        self.assertEqual(summary["synthesis_use"], expected_use)
                    if expected_status is not None:
                        self.assertEqual(result["status"], expected_status)
                    if expected_count is not None:
                        self.assertEqual(result["primary_input_count"], expected_count)





    def test_caller_provider_fields_cannot_create_independent_domains(self) -> None:
        cases = {
            "family labels": [{"provider_family": "anthropic"}, {"provider_family": "openai"}],
            "camp labels": [{"provider_camp": "anthropic"}, {"provider_camp": "google"}],
            "same provider under two labels": [{"provider_camp": "chatgpt"}, {"provider_family": "openai"}],
            "broker label": [{"provider_family": "openrouter"}, {"provider_family": "openai"}],
            "family and camp agree": [
                {"provider_family": "anthropic", "provider_camp": "anthropic"},
                {"provider_family": "openai", "provider_camp": "openai"},
            ],
        }
        claim = {"claim_id": "auth:jwt", "category": "auth", "key": "jwt", "value": "RS256 only"}
        for name, labels in cases.items():
            with self.subTest(case=name):
                result = evaluate_synthesis_inputs(
                    [
                        {"lane": f"lane-{index}", "disposition": "accepted", "zero_trust_claims": [claim], **fields}
                        for index, fields in enumerate(labels)
                    ],
                    zero_trust_required=True,
                )
                zero = result["zero_trust_consensus"]
                self.assertEqual(zero["independent_trust_domain_count"], 0)
                self.assertEqual(zero["consensus_status"], "blocked")
                self.assertTrue(result["blocked"])


class BoundAdjudicationTests(unittest.TestCase):
    def test_bound_acceptance_clears_a_tripwire_hold(self) -> None:
        records = [*PEERS, dispatch("d-held", "codex_architecture_critic")]
        result = run([tripwire_held("held", "d-held"), *peer_inputs()], records, [adjudication("adj-1", "d-held")])
        held = lane(result, "held")
        self.assertEqual(held["synthesis_use"], "primary")
        self.assertEqual(held["adjudication"]["state"], "applied")
        self.assertEqual(held["adjudication"]["adjudication_id"], "adj-1")
        self.assertTrue(held["implementation_blocked"])
        self.assertEqual(held["hold_reasons"], [TRIPWIRE])
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["primary_input_count"], 3)

    def test_accepted_with_changes_and_packet_only_go_hold(self) -> None:
        records = [*PEERS, dispatch("d-master", "chatgpt_pro_browser_master_reviewer")]
        entry = returned(
            "master", "d-master", recommended_synthesis_use="primary", implementation_blocked=True,
            hold_reasons=[PACKET_ONLY_GO],
        )
        record = adjudication("adj-go", "d-master", decision="accepted-with-changes", findings=(PACKET_ONLY_GO,))
        result = run([entry, *peer_inputs()], records, [record])
        self.assertEqual(lane(result, "master")["synthesis_use"], "primary")

    def test_historical_binding_context_family(self) -> None:
        rows = (
            ("test_changed_return_cannot_clear_a_hold", "return", CANDIDATE, "adj-old",
             {"return_sha256": sha("an earlier return")}, {}, "none", ["adj-old"], False, False),
            ("test_changed_candidate_cannot_clear_a_hold", "historical-candidate", CANDIDATE, "adj-old",
             {"candidate": OTHER_CANDIDATE}, {}, None, ["adj-old"], False, False),
            ("test_changed_candidate_cannot_clear_a_hold", "moved-dispatch", OTHER_CANDIDATE, "adj-1",
             {}, {}, None, None, True, False),
            ("test_changed_candidate_cannot_clear_a_hold", "candidate-absent", CANDIDATE, "adj-1",
             {}, {"candidate": None}, None, None, False, True),
            ("test_other_scope_cannot_clear_a_hold", "historical-scope", CANDIDATE, "adj-other",
             {"scope": "bead:another-task"}, {}, None, None, False, False),
            ("test_other_scope_cannot_clear_a_hold", "scope-absent", CANDIDATE, "adj-1",
             {}, {"scope": None}, None, None, False, False),
        )
        for row_id, case, dispatch_candidate, record_id, changes, options, state, history, unbound, no_domains in rows:
            with self.subTest(row=row_id, case=case):
                records = [*PEERS, dispatch("d-held", "codex_architecture_critic", candidate=dispatch_candidate)]
                record = adjudication(record_id, "d-held", **copy.deepcopy(changes))
                result = run([tripwire_held("held", "d-held"), *peer_inputs()], records, [record], **options)
                held = lane(result, "held")
                self.assertEqual(held["synthesis_use"], "open-risk")
                if state is not None:
                    self.assertEqual(held["adjudication"]["state"], state)
                if history is not None:
                    self.assertEqual(held["adjudication"]["historical_adjudication_ids"], history)
                if unbound:
                    self.assertFalse(held["dispatch_binding"]["bound"])
                if no_domains:
                    self.assertEqual(result["zero_trust_consensus"]["independent_trust_domain_count"], 0)

    def test_return_digest_differing_from_the_dispatch_record_is_unbound(self) -> None:
        records = [*PEERS, dispatch("d-held", "codex_architecture_critic")]
        entry = tripwire_held("held", "d-held", return_sha256=sha("replaced return text"))
        record = adjudication("adj-1", "d-held", return_sha256=sha("replaced return text"))
        result = run([entry, *peer_inputs()], records, [record])
        held = lane(result, "held")
        self.assertFalse(held["dispatch_binding"]["bound"])
        self.assertIn("return digest differs", " ".join(held["dispatch_binding"]["reasons"]))
        self.assertEqual(held["adjudication"]["state"], "unbound")
        self.assertEqual(held["synthesis_use"], "open-risk")



    def test_missing_or_self_referential_evidence_cannot_clear_a_hold(self) -> None:
        records = [*PEERS, dispatch("d-held", "codex_architecture_critic")]
        second = "return-tripwire:credential-request"
        cases = {
            "no evidence": adjudication("adj", "d-held", evidence=[]),
            "evidence omitted": {
                key: value for key, value in adjudication("adj", "d-held").items() if key != "supporting_evidence"
            },
            "evidence is the return itself": adjudication(
                "adj", "d-held",
                evidence=[{
                    "artifact": "returns/held.md", "artifact_type": "contractor-return",
                    "sha256": sha("return:d-held"), "finding_ids": [TRIPWIRE],
                }],
            ),
            "evidence covers one of two findings": adjudication(
                "adj", "d-held", findings=(TRIPWIRE, second),
                evidence=[{
                    "artifact": "log", "artifact_type": "validation-log", "sha256": sha("log"),
                    "finding_ids": [TRIPWIRE],
                }],
            ),
            "evidence digest malformed": adjudication(
                "adj", "d-held",
                evidence=[{"artifact": "log", "artifact_type": "validation-log", "sha256": "ABC", "finding_ids": [TRIPWIRE]}],
            ),
            "evidence type unknown": adjudication(
                "adj", "d-held",
                evidence=[{"artifact": "log", "artifact_type": "vibes", "sha256": sha("log"), "finding_ids": [TRIPWIRE]}],
            ),
            "evidence names an unadjudicated finding": adjudication(
                "adj", "d-held",
                evidence=[{
                    "artifact": "log", "artifact_type": "validation-log", "sha256": sha("log"),
                    "finding_ids": [TRIPWIRE, "unrelated"],
                }],
            ),
        }
        for name, record in cases.items():
            with self.subTest(case=name):
                result = run([tripwire_held("held", "d-held"), *peer_inputs()], records, [record])
                held = lane(result, "held")
                self.assertEqual(held["synthesis_use"], "open-risk")
                self.assertEqual(held["adjudication"]["state"], "invalid")
                self.assertTrue(held["adjudication"]["errors"])

    def test_forged_architect_authority_in_the_record_cannot_clear_a_hold(self) -> None:
        records = [*PEERS, dispatch("d-held", "codex_architecture_critic")]
        base = adjudication("adj", "d-held")
        cases = {
            "role only": {**base, "authority": {"role": "architect"}},
            "string authority": {**base, "authority": "architect"},
            "decision owner label": {
                **{key: value for key, value in base.items() if key != "authority"},
                "decision_owner": "architect",
            },
            "unconfigured rule": {**base, "authority": {"rule": "architect-override"}},
            "missing rationale": {**base, "rationale": ""},
            "missing adjudicator": {**base, "adjudicator": " "},
            "unknown decision": {**base, "decision": "approved"},
            "wrong record type": {**base, "record_type": "architect-approval"},
            "boolean version": {**base, "version": True},
        }
        for name, record in cases.items():
            with self.subTest(case=name):
                result = run([tripwire_held("held", "d-held"), *peer_inputs()], records, [record])
                self.assertEqual(lane(result, "held")["synthesis_use"], "open-risk")
                self.assertEqual(lane(result, "held")["adjudication"]["state"], "invalid")

    def test_malformed_dependency_data_cannot_clear_a_hold(self) -> None:
        good_records = [*PEERS, dispatch("d-held", "codex_architecture_critic")]
        good = adjudication("adj", "d-held")
        cases = {
            "dispatch records as an object": ({"d-held": good_records[-1]}, [good]),
            "duplicate dispatch records": ([*good_records, dispatch("d-held", "claude_architecture_critic")], [good]),
            "dispatch record without executor": (
                [*PEERS, {key: value for key, value in good_records[-1].items() if key != "executor"}], [good]),
            "dispatch record digest uppercase": (
                [*PEERS, {**good_records[-1], "return_sha256": sha("return:d-held").upper()}], [good]),
            "adjudications as an object": (good_records, {"adj": good}),
            "finding ids as a string": (good_records, [{**good, "finding_ids": TRIPWIRE}]),
            "duplicate finding ids": (good_records, [{**good, "finding_ids": [TRIPWIRE, TRIPWIRE]}]),
            "finding id not a string": (good_records, [{**good, "finding_ids": [{"id": TRIPWIRE}]}]),
            "evidence as an object": (good_records, [{**good, "supporting_evidence": {"artifact": "x"}}]),
        }
        for name, (records, adjudications) in cases.items():
            with self.subTest(case=name):
                result = run([tripwire_held("held", "d-held"), *peer_inputs()], records, adjudications)
                self.assertEqual(lane(result, "held")["synthesis_use"], "open-risk")
        held_without_reasons = returned(
            "held", "d-held", recommended_synthesis_use="primary", implementation_blocked=True, hold_reasons=[]
        )
        result = run([held_without_reasons, *peer_inputs()], good_records, [good])
        self.assertEqual(lane(result, "held")["synthesis_use"], "open-risk")

    def test_ambiguous_adjudication_cannot_clear_a_hold(self) -> None:
        records = [*PEERS, dispatch("d-held", "codex_architecture_critic")]
        cases = {
            "two current records": [adjudication("adj-1", "d-held"), adjudication("adj-2", "d-held")],
            "accept and reject": [adjudication("adj-1", "d-held"), adjudication("adj-2", "d-held", decision="rejected")],
            "valid plus malformed": [adjudication("adj-1", "d-held"), adjudication("adj-2", "d-held", evidence=[])],
        }
        for name, records_for_case in cases.items():
            with self.subTest(case=name):
                result = run([tripwire_held("held", "d-held"), *peer_inputs()], records, records_for_case)
                held = lane(result, "held")
                self.assertEqual(held["synthesis_use"], "open-risk")
                self.assertIn(held["adjudication"]["state"], {"ambiguous", "invalid"})

    def test_hold_reasons_must_each_be_named_and_clearable(self) -> None:
        records = [*PEERS, dispatch("d-held", "codex_architecture_critic")]
        two = tripwire_held("held", "d-held", hold_reasons=[TRIPWIRE, "return-tripwire:credential-request"])
        result = run([two, *peer_inputs()], records, [adjudication("adj", "d-held")])
        held = lane(result, "held")
        self.assertEqual(held["synthesis_use"], "open-risk")
        self.assertEqual(held["adjudication"]["uncleared_hold_reasons"], ["return-tripwire:credential-request"])

    def test_bound_acceptance_cannot_clear_peer_review_holds(self) -> None:
        records = [*PEERS, dispatch("d-held", "codex_architecture_critic")]
        for reasons in (
            ["peer-review-pending"],
            ["peer-review-pending", "provider-conflict-peer-review-pending"],
            ["peer-review-pending", "risk-review-pending"],
            [TRIPWIRE, "peer-review-pending"],
        ):
            with self.subTest(reasons=reasons):
                entry = tripwire_held("held", "d-held", hold_reasons=reasons)
                record = adjudication("adj", "d-held", findings=tuple(reasons))
                result = run([entry, *peer_inputs()], records, [record])
                held = lane(result, "held")
                self.assertEqual(held["synthesis_use"], "open-risk")
                self.assertTrue(held["adjudication"]["uncleared_hold_reasons"])

    def test_bound_rejection_resolves_the_use_hold_and_independent_work_continues(self) -> None:
        records = [*PEERS, dispatch("d-held", "codex_architecture_critic")]
        rejection = adjudication("adj-reject", "d-held", decision="rejected", evidence=[])
        result = run([tripwire_held("held", "d-held"), *peer_inputs()], records, [rejection])
        held = lane(result, "held")
        self.assertEqual(held["synthesis_use"], "reject")
        self.assertEqual(held["use_hold_resolved_by"], "adj-reject")
        self.assertTrue(held["implementation_blocked"])
        self.assertEqual(result["primary_input_count"], 2)
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["blocked"])
        # The same rejection without a binding resolves nothing.
        unbound = run([tripwire_held("held", "d-held"), *peer_inputs()], PEERS, [rejection])
        self.assertEqual(lane(unbound, "held")["synthesis_use"], "open-risk")
        self.assertIsNone(lane(unbound, "held")["use_hold_resolved_by"])

    def test_bound_rejection_of_a_quarantined_return_keeps_its_evaluated_disposition(self) -> None:
        records = [*PEERS, dispatch("d-taint", "gemini_architecture_critic")]
        entry = returned("taint", "d-taint", boundary_taint_status="boundary-tainted")
        rejection = adjudication("adj-reject", "d-taint", decision="rejected", evidence=[])
        result = run([entry, *peer_inputs()], records, [rejection])
        taint = lane(result, "taint")
        self.assertEqual(taint["synthesis_use"], "reject")
        self.assertEqual(taint["effective_disposition"], "boundary-tainted")
        self.assertEqual(taint["use_hold_resolved_by"], "adj-reject")
        self.assertEqual(result["status"], "partial")

    def test_bound_quarantine_blocks_only_that_return(self) -> None:
        records = [*PEERS, dispatch("d-third", "codex_architecture_critic")]
        quarantine = adjudication("adj-q", "d-third", decision="quarantined", evidence=[])
        result = run([returned("third", "d-third"), *peer_inputs()], records, [quarantine])
        self.assertEqual(lane(result, "third")["synthesis_use"], "quarantine")
        self.assertEqual(lane(result, "opus")["synthesis_use"], "primary")
        self.assertEqual(lane(result, "chatgpt")["synthesis_use"], "primary")
        self.assertEqual(result["status"], "partial")

    def test_bound_acceptance_upgrades_a_salvage_only_provider(self) -> None:
        records = [*PEERS, dispatch("d-gemini", "gemini_architecture_critic")]
        entry = returned("gemini", "d-gemini", synthesis_use="primary")
        record = adjudication("adj-g", "d-gemini", findings=("finding:cipher-mode",))
        result = run([entry, returned("opus", "d-opus")], records, [record])
        self.assertEqual(lane(result, "gemini")["synthesis_use"], "primary")
        self.assertEqual(result["status"], "ready")

    def test_historical_records_stay_readable_without_granting_use(self) -> None:
        records = [*PEERS, dispatch("d-held", "codex_architecture_critic")]
        legacy = tripwire_held("held", "d-held", architect_adjudicated=True, synthesis_use_authority="architect")
        history = [
            adjudication("adj-2025", "d-held", return_sha256=sha("first return")),
            adjudication("adj-old-candidate", "d-held", candidate=OTHER_CANDIDATE),
        ]
        result = run([legacy, *peer_inputs()], records, history)
        held = lane(result, "held")
        self.assertEqual(held["synthesis_use"], "open-risk")
        self.assertEqual(held["ignored_authority_claims"], ["architect_adjudicated", "synthesis_use_authority"])
        self.assertEqual(held["adjudication"]["historical_adjudication_ids"], ["adj-2025", "adj-old-candidate"])
        current = run([legacy, *peer_inputs()], records, [*history, adjudication("adj-now", "d-held")])
        self.assertEqual(lane(current, "held")["synthesis_use"], "primary")
        self.assertEqual(lane(current, "held")["adjudication"]["adjudication_id"], "adj-now")

    def test_unmatched_adjudications_are_reported_and_not_applied(self) -> None:
        # A well-formed record for a dispatch no input names is reported and
        # restricts nothing present.
        result = run(peer_inputs(), PEERS, [adjudication("adj-x", "d-nobody")])
        self.assertEqual(len(result["adjudication_errors"]), 1)
        self.assertEqual(result["status"], "ready")
        # Round 7: a record that is not an object cannot be shown to concern
        # another input, so it is unresolved for every input and blocks.
        result = run(peer_inputs(), PEERS, [adjudication("adj-x", "d-nobody"), "not a record"])
        self.assertEqual(len(result["adjudication_errors"]), 2)
        self.assertEqual(result["status"], "blocked")

    def test_hashed_cooperative_records_are_not_trusted_host_authority(self) -> None:
        records = [
            {**PEERS[0], "record_sha256": sha("self"), "trusted_host": True, "enforcement": "trusted-host"},
            PEERS[1],
            dispatch("d-held", "codex_architecture_critic", record_sha256=sha("self")),
        ]
        record = adjudication("adj-1", "d-held", trusted_host=True, record_sha256=sha("self"))
        result = run([tripwire_held("held", "d-held"), *peer_inputs()], records, [record])
        self.assertEqual(result["authority_enforcement"], "cooperative")
        self.assertIs(result["trusted_host_authority"], False)

    def test_evaluation_has_no_side_effects(self) -> None:
        records = [*PEERS, dispatch("d-held", "codex_architecture_critic")]
        inputs = [tripwire_held("held", "d-held"), *peer_inputs()]
        adjudications = [adjudication("adj-1", "d-held")]
        before = copy.deepcopy((inputs, records, adjudications))
        with mock.patch("subprocess.run", side_effect=AssertionError("subprocess")) as spawn, \
                mock.patch("subprocess.Popen", side_effect=AssertionError("subprocess")) as popen, \
                mock.patch("cwo_core.audit.record_audit_event", side_effect=AssertionError("audit")) as audit:
            run(inputs, records, adjudications, zero_trust_required=True)
        self.assertEqual((spawn.call_count, popen.call_count, audit.call_count), (0, 0, 0))
        self.assertEqual(before, (inputs, records, adjudications))


class DispatchProvenanceTests(unittest.TestCase):
    claim = {"claim_id": "auth:jwt", "category": "auth", "key": "jwt", "value": "RS256 only"}

    def zero(self, inputs: list[dict], records: list[dict]) -> dict:
        for entry in inputs:
            entry.setdefault("zero_trust_claims", [self.claim])
        return run(inputs, records, zero_trust_required=True)

    def test_bound_different_providers_remain_countable(self) -> None:
        result = self.zero(peer_inputs(), PEERS)
        zero = result["zero_trust_consensus"]
        self.assertEqual(zero["independent_trust_domains"], ["anthropic", "openai"])
        self.assertEqual(zero["consensus_status"], "informational")
        self.assertFalse(result["blocked"])
        sources = {item["source_field"] for item in zero["trust_domain_summaries"]}
        self.assertEqual(sources, {"dispatch-record"})

    def test_same_provider_returns_count_once(self) -> None:
        records = [
            dispatch("d-chatgpt", "chatgpt_pro_browser_master_reviewer"),
            dispatch("d-codex", "codex_architecture_critic"),
            dispatch("d-worker", "internal_worker"),
        ]
        inputs = [returned("chatgpt", "d-chatgpt"), returned("codex", "d-codex"), returned("worker", "d-worker")]
        zero = self.zero(inputs, records)["zero_trust_consensus"]
        self.assertEqual(zero["independent_trust_domains"], ["openai"])
        self.assertEqual(zero["consensus_status"], "blocked")
        local = [dispatch("d-a", "openshift_ai_vllm_worker"), dispatch("d-b", "local_openai_compatible_worker")]
        zero = self.zero([returned("a", "d-a"), returned("b", "d-b")], local)["zero_trust_consensus"]
        self.assertEqual(zero["independent_trust_domains"], ["local"])

    def test_caller_labels_on_bound_returns_cannot_change_the_domain(self) -> None:
        for fields in (
            {"provider_family": "google"},
            {"provider_camp": "anthropic"},
            {"trust_domain": "human"},
            {"provider_family": "openrouter"},
            {"provider_camp": "chatgpt"},
        ):
            with self.subTest(fields=fields):
                inputs = [returned("opus", "d-opus"), returned("chatgpt", "d-chatgpt", **fields)]
                zero = self.zero(inputs, PEERS)["zero_trust_consensus"]
                summary = next(item for item in zero["trust_domain_summaries"] if item["lane"] == "chatgpt")
                self.assertEqual(summary["source_field"], "conflict")
                self.assertFalse(summary["included_for_independence"])
                self.assertEqual(zero["independent_trust_domain_count"], 1)
        agreeing = [returned("opus", "d-opus", provider_family="anthropic"), returned("chatgpt", "d-chatgpt", provider_camp="codex")]
        self.assertEqual(self.zero(agreeing, PEERS)["zero_trust_consensus"]["independent_trust_domain_count"], 2)

    def test_identity_labels_on_the_dispatch_record_cannot_change_the_domain(self) -> None:
        for extra in (
            {"provider_family": "openrouter"},
            {"provider_key": "google_gemini_manual"},
            {"underlying_provider_key": "anthropic_manual"},
        ):
            with self.subTest(extra=extra):
                records = [PEERS[0], {**PEERS[1], **extra}]
                zero = self.zero(peer_inputs(), records)["zero_trust_consensus"]
                summary = next(item for item in zero["trust_domain_summaries"] if item["lane"] == "chatgpt")
                self.assertEqual(summary["source_field"], "provenance-unknown")
                self.assertEqual(zero["independent_trust_domain_count"], 1)

    def test_one_dispatch_cannot_stand_behind_two_inputs(self) -> None:
        duplicate = [returned("opus", "d-opus"), returned("opus-again", "d-opus"), returned("chatgpt", "d-chatgpt")]
        result = self.zero(duplicate, PEERS)
        for name in ("opus", "opus-again"):
            self.assertFalse(lane(result, name)["dispatch_binding"]["bound"])
        self.assertEqual(result["zero_trust_consensus"]["independent_trust_domains"], ["openai"])
        records = [*PEERS, dispatch("d-held", "codex_architecture_critic")]
        held = [tripwire_held("held", "d-held"), tripwire_held("held-copy", "d-held"), *peer_inputs()]
        result = run(held, records, [adjudication("adj-1", "d-held")])
        self.assertEqual(lane(result, "held")["synthesis_use"], "open-risk")
        self.assertEqual(lane(result, "held-copy")["synthesis_use"], "open-risk")

    def test_unknown_executor_or_unbound_return_is_not_counted(self) -> None:
        records = [PEERS[0], dispatch("d-chatgpt", "openrouter_fusion_reviewer")]
        zero = self.zero(peer_inputs(), records)["zero_trust_consensus"]
        self.assertEqual(zero["independent_trust_domain_count"], 1)
        zero = self.zero([returned("opus", "d-opus"), returned("chatgpt", provider_family="openai")], PEERS)["zero_trust_consensus"]
        summary = next(item for item in zero["trust_domain_summaries"] if item["lane"] == "chatgpt")
        self.assertEqual(summary["source_field"], "unbound")
        self.assertEqual(zero["independent_trust_domain_count"], 1)

    def test_salvage_only_rule_follows_the_dispatch_family(self) -> None:
        records = [*PEERS, dispatch("d-gemini", "gemini_architecture_critic")]
        for fields in ({}, {"provider_camp": "openai"}, {"provider_camp": "anthropic", "provider_family": "anthropic"}):
            with self.subTest(fields=fields):
                result = run([returned("gemini", "d-gemini", **fields), returned("opus", "d-opus")], records)
                self.assertEqual(lane(result, "gemini")["synthesis_use"], "salvage-only")
                self.assertEqual(result["status"], "blocked")

    def test_broker_resolves_only_to_a_configured_observed_underlying_provider(self) -> None:
        from cwo_core.adjudication import dispatch_provenance

        executors = {"executors": {"fusion": {"provider_key": "broker"}, "direct": {"provider_key": "anthropic_api"}}}
        providers = {
            "providers": {
                "broker": {"family": "openrouter", "broker": True, "underlying_providers": ["anthropic_api", "nested"]},
                "anthropic_api": {"family": "anthropic"},
                "openai_api": {"family": "openai"},
                "nested": {"family": "openrouter", "broker": True},
            }
        }

        def provenance(**extra: object) -> dict:
            return dispatch_provenance(
                dispatch("d", "fusion", **extra), executor_registry=executors, provider_registry=providers
            )

        self.assertFalse(provenance()["known"])
        self.assertFalse(provenance(underlying_provider_key="openai_api")["known"])
        self.assertFalse(provenance(underlying_provider_key="nested")["known"])
        self.assertFalse(provenance(underlying_provider_key="anthropic_api", provider_family="openrouter")["known"])
        resolved = provenance(underlying_provider_key="anthropic_api")
        self.assertTrue(resolved["known"])
        self.assertEqual(
            (resolved["provider_key"], resolved["underlying_provider_key"], resolved["provider_family"]),
            ("broker", "anthropic_api", "anthropic"),
        )
        direct = dispatch_provenance(dispatch("d", "direct"), executor_registry=executors, provider_registry=providers)
        self.assertEqual(direct["provider_family"], "anthropic")
        self.assertFalse(
            dispatch_provenance(
                dispatch("d", "direct", underlying_provider_key="openai_api"),
                executor_registry=executors, provider_registry=providers,
            )["known"]
        )



# Values that are not scalars of the expected kind. Each malformed record must
# yield a rejection for that record only; nothing raises and unrelated inputs
# keep their use.
def malformed_values(valid: object) -> dict:
    return {"empty array": [], "empty object": {}, "array": [valid], "object": {"value": valid}}


EXTERNAL_BLOCK = "all external inputs are quarantined or boundary-tainted"
MINIMUM_BLOCK = "fewer than minimum_usable_inputs accepted or accepted-with-modification inputs"


def rejections(result: dict, source: str) -> list[dict]:
    return [item for item in result["record_rejections"] if item["source"] == source]


class ConflictingProvenanceTests(unittest.TestCase):
    """Conflicting or unknown provenance never makes a return more eligible."""

    claim = {"claim_id": "auth:jwt", "category": "auth", "key": "jwt", "value": "RS256 only"}

    def test_conflicting_dispatch_labels_keep_the_salvage_restriction(self) -> None:
        for extra in (
            {"provider_family": "openai"},
            {"provider_key": "openai_manual"},
            {"underlying_provider_key": "openai_manual"},
            {"provider_family": "openai", "provider_key": "openai_manual"},
        ):
            for labels in ({}, {"provider_camp": "openai"}, {"provider_camp": "openai", "provider_family": "openai"}):
                with self.subTest(record=extra, labels=labels):
                    records = [*PEERS, dispatch("d-gemini", "gemini_architecture_critic", **extra)]
                    inputs = [returned("gemini", "d-gemini", zero_trust_claims=[self.claim], **labels),
                              returned("opus", "d-opus", zero_trust_claims=[self.claim])]
                    result = run(inputs, records, zero_trust_required=True)
                    gemini = lane(result, "gemini")
                    self.assertFalse(gemini["dispatch_binding"]["provenance_known"])
                    self.assertEqual(gemini["synthesis_use"], "salvage-only")
                    self.assertEqual(result["primary_input_count"], 1)
                    self.assertEqual(result["status"], "blocked")
                    zero = result["zero_trust_consensus"]
                    self.assertEqual(zero["independent_trust_domains"], ["anthropic"])
                    summary = next(item for item in zero["trust_domain_summaries"] if item["lane"] == "gemini")
                    self.assertFalse(summary["included_for_independence"])

    def test_unknown_or_conflicting_provenance_is_excluded_from_primary_use(self) -> None:
        cases = {
            "record family conflicts": dispatch("d-x", "chatgpt_pro_browser_master_reviewer", provider_family="anthropic"),
            "record provider conflicts": dispatch("d-x", "claude_architecture_critic", provider_key="openai_manual"),
            "unregistered executor": dispatch("d-x", "openrouter_fusion_reviewer"),
        }
        for name, record in cases.items():
            with self.subTest(case=name):
                result = run([returned("x", "d-x"), returned("opus", "d-opus")], [*PEERS, record])
                self.assertNotEqual(lane(result, "x")["synthesis_use"], "primary")
                self.assertEqual(result["status"], "blocked")
                # A bound acceptance does not lift it: the identity is still unknown.
                accepted = run(
                    [returned("x", "d-x", synthesis_use="primary"), returned("opus", "d-opus")],
                    [*PEERS, record],
                    [adjudication("adj-x", "d-x", findings=("finding:x",))],
                )
                self.assertNotEqual(lane(accepted, "x")["synthesis_use"], "primary")
                self.assertEqual(accepted["status"], "blocked")

    def test_salvage_label_on_any_provider_field_adds_the_restriction(self) -> None:
        for labels in ({"provider_family": "google"}, {"trust_domain": "google"}, {"provider_camp": "Google"}):
            with self.subTest(labels=labels):
                result = evaluate_synthesis_inputs(
                    [{"lane": "gemini", "disposition": "accepted", **labels},
                     {"lane": "opus", "disposition": "accepted"}]
                )
                self.assertEqual(result["input_summaries"][0]["synthesis_use"], "salvage-only")
                self.assertEqual(result["status"], "blocked")

    def test_malformed_provider_labels_are_never_primary(self) -> None:
        for field in ("provider_camp", "provider_family", "trust_domain"):
            for name, value in malformed_values("google").items():
                with self.subTest(field=field, value=name):
                    result = evaluate_synthesis_inputs(
                        [{"lane": "gemini", "disposition": "accepted", field: value},
                         {"lane": "opus", "disposition": "accepted"}]
                    )
                    self.assertNotEqual(result["input_summaries"][0]["synthesis_use"], "primary")
                    self.assertEqual(result["input_summaries"][1]["synthesis_use"], "primary")
                    self.assertEqual(result["status"], "blocked")
                    self.assertEqual([item["index"] for item in rejections(result, "inputs")], [0])

    def test_broker_and_direct_returns_for_one_provider_count_as_one_domain(self) -> None:
        import cwo_core.adjudication as adjudication_module

        fake = {
            "executor-registry": {
                "executors": {
                    "fusion": {"provider_key": "broker"},
                    "direct_anthropic": {"provider_key": "anthropic_api"},
                    "direct_openai": {"provider_key": "openai_api"},
                }
            },
            "provider-registry": {
                "providers": {
                    "broker": {"family": "openrouter", "broker": True, "underlying_providers": ["anthropic_api", "openai_api"]},
                    "anthropic_api": {"family": "anthropic"},
                    "openai_api": {"family": "openai"},
                }
            },
        }
        real = adjudication_module.load_policy

        def load(name: str) -> dict:
            return fake[name] if name in fake else real(name)

        records = [
            dispatch("d-broker", "fusion", underlying_provider_key="anthropic_api"),
            dispatch("d-direct", "direct_anthropic"),
            dispatch("d-openai", "direct_openai"),
        ]
        inputs = [
            returned("broker", "d-broker", zero_trust_claims=[self.claim]),
            returned("direct", "d-direct", zero_trust_claims=[self.claim]),
        ]
        with mock.patch.object(adjudication_module, "load_policy", side_effect=load):
            same = run(copy.deepcopy(inputs), records, zero_trust_required=True)
            mixed = run(
                [*copy.deepcopy(inputs), returned("openai", "d-openai", zero_trust_claims=[self.claim])],
                records,
                zero_trust_required=True,
            )
        zero = same["zero_trust_consensus"]
        self.assertEqual(lane(same, "broker")["dispatch_binding"]["provider_key"], "broker")
        self.assertEqual(lane(same, "broker")["dispatch_binding"]["underlying_provider_key"], "anthropic_api")
        self.assertEqual([item["included_for_independence"] for item in zero["trust_domain_summaries"]], [True, True])
        self.assertEqual(zero["independent_trust_domains"], ["anthropic"])
        self.assertEqual(zero["consensus_status"], "blocked")
        self.assertEqual(mixed["zero_trust_consensus"]["independent_trust_domains"], ["anthropic", "openai"])
        self.assertFalse(mixed["blocked"])

    def test_non_boolean_broker_flag_leaves_provenance_unknown(self) -> None:
        from cwo_core.adjudication import dispatch_provenance

        executors = {"executors": {"fusion": {"provider_key": "broker"}}}
        for flag in ("true", "false", 1, 0, [], {}, None):
            with self.subTest(flag=flag):
                providers = {
                    "providers": {
                        "broker": {"family": "openrouter", "broker": flag, "underlying_providers": ["anthropic_api"]},
                        "anthropic_api": {"family": "anthropic"},
                    }
                }
                for extra in ({}, {"underlying_provider_key": "anthropic_api"}):
                    provenance = dispatch_provenance(
                        dispatch("d", "fusion", **extra), executor_registry=executors, provider_registry=providers
                    )
                    self.assertFalse(provenance["known"])


class SynthesisUseValidationTests(unittest.TestCase):
    """An invalid explicit or recommended use never widens eligibility."""

    INVALID = {
        "unknown string": "invalid",
        "empty string": "",
        "near miss": "definitely-primary",
        "integer": 1,
        "zero": 0,
        "float": 2.5,
        "true": True,
        "false": False,
        "empty array": [],
        "array": ["primary"],
        "empty object": {},
        "object": {"use": "primary"},
    }

    def test_invalid_use_recommendation_family(self) -> None:
        rows = (
            ("test_invalid_explicit_use_cannot_bypass_a_primary_recommendation",
             "synthesis_use", "primary", True, None, True, False),
            ("test_invalid_explicit_use_keeps_a_restrictive_recommendation",
             "synthesis_use", "salvage-only", False, "salvage-only", False, True),
            ("test_invalid_recommended_use_is_never_primary",
             "recommended_synthesis_use", None, False, None, False, False),
        )
        for row_id, field, recommendation, include_null, expected_use, check_control, check_rejection in rows:
            values = {**self.INVALID, "null": None} if include_null else self.INVALID
            for name, value in values.items():
                with self.subTest(row=row_id, value=name):
                    entry = {"lane": "opus", "disposition": "accepted"}
                    if recommendation is not None:
                        entry["recommended_synthesis_use"] = recommendation
                    entry[field] = copy.deepcopy(value)
                    result = evaluate_synthesis_inputs([entry, {"lane": "chatgpt", "disposition": "accepted"}])
                    if expected_use is None:
                        self.assertNotEqual(result["input_summaries"][0]["synthesis_use"], "primary")
                    else:
                        self.assertEqual(result["input_summaries"][0]["synthesis_use"], expected_use)
                    if check_control:
                        self.assertEqual(result["input_summaries"][1]["synthesis_use"], "primary")
                    self.assertEqual(result["status"], "blocked")
                    if check_rejection:
                        self.assertEqual([item["index"] for item in rejections(result, "inputs")], [0])



    def test_invalid_explicit_use_is_not_laundered_by_a_bound_acceptance(self) -> None:
        records = [*PEERS, dispatch("d-held", "codex_architecture_critic")]
        for name, value in self.INVALID.items():
            with self.subTest(value=name):
                entry = returned("held", "d-held", recommended_synthesis_use="primary", synthesis_use=value)
                result = run([entry, returned("opus", "d-opus")], records,
                             [adjudication("adj-1", "d-held", findings=("finding:x",))])
                self.assertNotEqual(lane(result, "held")["synthesis_use"], "primary")
                self.assertEqual(result["status"], "blocked")


class MalformedRecordTests(unittest.TestCase):
    """Each malformed record is rejected on its own; nothing raises and other inputs continue."""

    def scenario(self, *, held_record: dict | None = None, held_adjudication: dict | None = None) -> dict:
        records = [*PEERS, held_record or dispatch("d-held", "codex_architecture_critic"),
                   dispatch("d-other", "codex_architecture_critic")]
        adjudications = [held_adjudication or adjudication("adj-held", "d-held"), adjudication("adj-other", "d-other")]
        inputs = [tripwire_held("held", "d-held"), tripwire_held("other", "d-other"), *peer_inputs()]
        return run(inputs, records, adjudications)

    def assert_contained(self, result: dict) -> None:
        self.assertNotEqual(lane(result, "held")["synthesis_use"], "primary")
        other = lane(result, "other")
        self.assertEqual(other["synthesis_use"], "primary")
        self.assertEqual(other["adjudication"]["state"], "applied")
        self.assertEqual(other["adjudication"]["errors"], [])
        self.assertEqual(lane(result, "opus")["synthesis_use"], "primary")
        self.assertEqual(lane(result, "chatgpt")["synthesis_use"], "primary")
        self.assertEqual(result["primary_input_count"], 3)

    def test_dispatch_record_scalar_fields(self) -> None:
        base = dispatch("d-held", "codex_architecture_critic")
        fields = {
            "record_type": base["record_type"], "version": 1, "dispatch_id": "d-held",
            "executor": base["executor"], "return_sha256": base["return_sha256"], "candidate": CANDIDATE,
            "provider_key": "internal_codex", "provider_family": "openai", "underlying_provider_key": "internal_codex",
        }
        for field, valid in fields.items():
            for name, value in malformed_values(valid).items():
                with self.subTest(field=field, value=name):
                    result = self.scenario(held_record={**base, field: value})
                    if field == "dispatch_id":
                        # Round 8: a record whose dispatch_id cannot be read may be a second record for any
                        # dispatch, so no attempted binding holds beside it (it used to leave the others bound).
                        self.assertEqual(result["primary_input_count"], 0)
                        self.assertEqual(result["status"], "blocked")
                        for name_ in ("held", "other", "opus", "chatgpt"):
                            binding = lane(result, name_)["dispatch_binding"]
                            self.assertFalse(binding["bound"])
                            self.assertIn(WILDCARD_RECORD_REASON, binding["reasons"])
                    else:
                        self.assert_contained(result)
                    self.assertFalse(lane(result, "held")["dispatch_binding"]["bound"])
                    self.assertEqual([item["index"] for item in rejections(result, "dispatch_records")], [2])
                    self.assertTrue(rejections(result, "dispatch_records")[0]["errors"])

    def test_adjudication_record_scalar_fields(self) -> None:
        base = adjudication("adj-held", "d-held")
        fields = {
            "record_type": base["record_type"], "version": 1, "adjudication_id": "adj-held", "dispatch_id": "d-held",
            "return_sha256": base["return_sha256"], "candidate": CANDIDATE, "scope": SCOPE, "decision": "accepted",
            "rationale": base["rationale"], "adjudicator": base["adjudicator"], "authority": base["authority"],
            "finding_ids": base["finding_ids"],
        }
        for field, valid in fields.items():
            for name, value in malformed_values(valid).items():
                with self.subTest(field=field, value=name):
                    result = self.scenario(held_adjudication={**base, field: value})
                    self.assert_contained(result)
                    self.assertEqual([item["index"] for item in rejections(result, "adjudications")], [0])
        for name, value in malformed_values(RULE).items():
            with self.subTest(field="authority.rule", value=name):
                result = self.scenario(held_adjudication={**base, "authority": {"rule": value}})
                self.assert_contained(result)
                self.assertEqual([item["index"] for item in rejections(result, "adjudications")], [0])
        for name, value in malformed_values(TRIPWIRE).items():
            with self.subTest(field="finding_ids[0]", value=name):
                result = self.scenario(held_adjudication={**base, "finding_ids": [value]})
                self.assert_contained(result)
                self.assertEqual([item["index"] for item in rejections(result, "adjudications")], [0])
                self.assertEqual(lane(result, "held")["adjudication"]["state"], "invalid")

    def test_supporting_evidence_scalar_fields(self) -> None:
        item = adjudication("adj-held", "d-held")["supporting_evidence"][0]
        fields = {
            "artifact": item["artifact"], "artifact_type": item["artifact_type"], "sha256": item["sha256"],
            "finding_ids": item["finding_ids"],
        }
        for field, valid in fields.items():
            for name, value in malformed_values(valid).items():
                with self.subTest(field=field, value=name):
                    record = adjudication("adj-held", "d-held", evidence=[{**item, field: value}])
                    result = self.scenario(held_adjudication=record)
                    self.assert_contained(result)
                    held = lane(result, "held")
                    self.assertEqual(held["adjudication"]["state"], "invalid")
                    self.assertTrue(any("supporting_evidence[0]" in error for error in held["adjudication"]["errors"]))
                    self.assertEqual([entry["index"] for entry in rejections(result, "adjudications")], [0])
        for name, value in malformed_values(TRIPWIRE).items():
            with self.subTest(field="finding_ids[0]", value=name):
                record = adjudication("adj-held", "d-held", evidence=[{**item, "finding_ids": [value]}])
                result = self.scenario(held_adjudication=record)
                self.assert_contained(result)
                self.assertEqual(lane(result, "held")["adjudication"]["state"], "invalid")

    def test_malformed_input_fields_never_widen_use(self) -> None:
        records = [*PEERS, dispatch("d-held", "codex_architecture_critic")]
        cases = {
            "hold flag as an array": returned("held", implementation_blocked=[True], hold_reasons=[TRIPWIRE]),
            "hold flag as an object": returned("held", implementation_blocked={"value": True}, hold_reasons=[TRIPWIRE]),
            "hold flag as an unknown string": returned("held", implementation_blocked="pending", hold_reasons=[TRIPWIRE]),
            "hold flag as a float": returned("held", implementation_blocked=0.5, hold_reasons=[TRIPWIRE]),
            "hold reasons as a number": returned("held", implementation_blocked=True, hold_reasons=7),
            "hold reasons as null": returned("held", implementation_blocked=True, hold_reasons=None),
            "hold reasons as an object": tripwire_held("held", "d-held", hold_reasons={TRIPWIRE: True}),
            "hold reasons as a string": tripwire_held("held", "d-held", hold_reasons=TRIPWIRE),
            "hold reason as an array": tripwire_held("held", "d-held", hold_reasons=[[TRIPWIRE]]),
            "boundary status as an array": returned("held", boundary_taint_status=["boundary-tainted"]),
            "boundary status as an object": returned("held", boundary_status={"value": "boundary-tainted"}),
            "boundary statuses conflict": returned("held", boundary_taint_status="clear", boundary_status="boundary-tainted"),
            "claims as a number": returned("held", "d-held", zero_trust_claims=5),
            "claims as an object": returned("held", "d-held", zero_trust_claims={"auth:jwt": "RS256"}),
        }
        for name, entry in cases.items():
            with self.subTest(case=name):
                result = run([entry, *peer_inputs()], records, [adjudication("adj-held", "d-held")],
                             zero_trust_required="claims" in name)
                held = lane(result, "held")
                if "claims" in name:
                    self.assertEqual(held["synthesis_use"], "primary")
                else:
                    self.assertNotEqual(held["synthesis_use"], "primary")
                self.assertEqual(lane(result, "opus")["synthesis_use"], "primary")
                self.assertEqual(lane(result, "chatgpt")["synthesis_use"], "primary")

    def test_non_integer_record_versions_are_rejected(self) -> None:
        for value in (1.0, "1", True):
            with self.subTest(record="dispatch", version=value):
                result = self.scenario(held_record={**dispatch("d-held", "codex_architecture_critic"), "version": value})
                self.assert_contained(result)
                self.assertEqual([item["index"] for item in rejections(result, "dispatch_records")], [2])
            with self.subTest(record="adjudication", version=value):
                result = self.scenario(held_adjudication=adjudication("adj-held", "d-held", version=value))
                self.assert_contained(result)
                self.assertEqual([item["index"] for item in rejections(result, "adjudications")], [0])

    def test_unreadable_disposition_is_not_promoted_by_a_bound_acceptance(self) -> None:
        records = [*PEERS, dispatch("d-held", "codex_architecture_critic")]
        for value in (["accepted"], {"value": "accepted"}, 7, "approved"):
            with self.subTest(disposition=value):
                entry = returned("held", "d-held", disposition=value, synthesis_use="primary")
                result = run([entry, *peer_inputs()], records, [adjudication("adj-held", "d-held", findings=("finding:x",))])
                self.assertNotEqual(lane(result, "held")["synthesis_use"], "primary")
                self.assertEqual(result["primary_input_count"], 2)

    def test_malformed_external_flag_cannot_lift_the_external_input_block(self) -> None:
        local = [{"lane": "a", "disposition": "accepted", "external": False},
                 {"lane": "b", "disposition": "accepted", "external": False}]
        for value in ("false", "true", "", 0, 1, None, [], {}):
            with self.subTest(on="accepted input", external=value):
                result = evaluate_synthesis_inputs(
                    [{"lane": "q", "disposition": "quarantined"}, *local,
                     {"lane": "c", "disposition": "accepted", "external": value}]
                )
                self.assertIn("all external inputs are quarantined or boundary-tainted", result["blocked_reasons"])
                self.assertEqual([item["index"] for item in rejections(result, "inputs")], [3])
            with self.subTest(on="quarantined input", external=value):
                result = evaluate_synthesis_inputs([{"lane": "q", "disposition": "quarantined", "external": value}, *local])
                self.assertIn("all external inputs are quarantined or boundary-tainted", result["blocked_reasons"])
        result = evaluate_synthesis_inputs([{"lane": "q", "disposition": "quarantined"}, "not a record", *local])
        self.assertIn("all external inputs are quarantined or boundary-tainted", result["blocked_reasons"])

    def test_non_object_inputs_are_rejected_and_others_continue(self) -> None:
        for value in ("not a record", 7, None, ["lane"]):
            with self.subTest(value=value):
                result = run([value, *peer_inputs()], PEERS, zero_trust_required=True)
                self.assertEqual(result["input_summaries"][0]["synthesis_use"], "reject")
                self.assertEqual([item["index"] for item in rejections(result, "inputs")], [0])
                # Round 8: a record that cannot be read may claim any dispatch, so the attempted bindings
                # beside it do not hold (they used to stay primary and count two trust domains).
                for name in ("opus", "chatgpt"):
                    self.assertNotEqual(lane(result, name)["synthesis_use"], "primary")
                    self.assertIn(WILDCARD_INPUT_REASON, lane(result, name)["dispatch_binding"]["reasons"])
                self.assertEqual(result["zero_trust_consensus"]["independent_trust_domains"], [])
                self.assertEqual(result["status"], "blocked")
                # Inputs that attempt no binding (legacy inputs) continue.
                legacy = run([value, returned("opus"), returned("chatgpt")], [])
                self.assertEqual(lane(legacy, "opus")["synthesis_use"], "primary")
                self.assertEqual(lane(legacy, "chatgpt")["synthesis_use"], "primary")
                self.assertEqual(legacy["primary_input_count"], 2)


class ExactClearableReasonTests(unittest.TestCase):
    def test_extended_reasons_are_not_clearable(self) -> None:
        records = [*PEERS, dispatch("d-held", "codex_architecture_critic")]
        control = run([tripwire_held("held", "d-held"), *peer_inputs()], records,
                      [adjudication("adj", "d-held")])
        self.assertEqual(lane(control, "held")["synthesis_use"], "primary")
        self.assertTrue(lane(control, "held")["adjudication"]["authorizes_requested_use"])
        for reason in (
            "unrelated-hold::review-suppression",
            PACKET_ONLY_GO + "; risk-review-pending",
            "prefix " + PACKET_ONLY_GO,
            "return-tripwire:review-suppression; peer-review-pending",
            "return-tripwire:",
            "return-tripwire: peer-review-pending",
        ):
            with self.subTest(reason=reason):
                entry = tripwire_held("held", "d-held", hold_reasons=[reason])
                result = run([entry, *peer_inputs()], records, [adjudication("adj", "d-held", findings=(reason,))])
                held = lane(result, "held")
                self.assertEqual(held["synthesis_use"], "open-risk")
                self.assertEqual(held["adjudication"]["uncleared_hold_reasons"], [reason])


# Round 3: a failure is not an absence. Every case starts from an accepted,
# otherwise unheld input that is primary on the valid path, next to one
# control, so the valid path is "ready" and any failure must turn it "blocked".
def accepted_unheld(lane_name: str, dispatch_id: str | None, **fields: object) -> dict:
    return returned(lane_name, dispatch_id, **fields)


def recommended_primary(lane_name: str, dispatch_id: str | None, **fields: object) -> dict:
    return returned(lane_name, dispatch_id, recommended_synthesis_use="primary", **fields)


CONTROL = dispatch("d-opus", "claude_architecture_critic")


def control_input() -> dict:
    return returned("opus", "d-opus")


def acceptance(adjudication_id: str, dispatch_id: str, **overrides: object) -> dict:
    return adjudication(adjudication_id, dispatch_id, findings=("finding:x",), **overrides)


# Each failed or ambiguous attempted binding, as a change to the subject's
# dispatch records or input fields. The subject's valid dispatch is
# ``d-subject``; each case returns (records, input overrides).
def failed_bindings(executor: str) -> dict:
    valid = dispatch("d-subject", executor)
    return {
        "record provider_family is an array": ([{**valid, "provider_family": []}], {}),
        "record provider_key is an object": ([{**valid, "provider_key": {}}], {}),
        "record version is 1.0": ([{**valid, "version": 1.0}], {}),
        "record version is a string": ([{**valid, "version": "1"}], {}),
        "record executor is an array": ([{**valid, "executor": [executor]}], {}),
        "record type is wrong": ([{**valid, "record_type": "dispatch"}], {}),
        "dispatch is duplicated": ([valid, copy.deepcopy(valid)], {}),
        "dispatch duplicated with another executor": ([valid, dispatch("d-subject", "claude_architecture_critic")], {}),
        "record for another candidate": ([dispatch("d-subject", executor, candidate=OTHER_CANDIDATE)], {}),
        "return digest differs": ([valid], {"return_sha256": sha("replaced return")}),
        "input digest uppercase": ([valid], {"return_sha256": sha("return:d-subject").upper()}),
        "input digest null": ([valid], {"return_sha256": None}),
        "input names no digest": ([valid], {"return_sha256": "__drop__"}),
        "input dispatch_id is an array": ([valid], {"dispatch_id": ["d-subject"]}),
        "input dispatch_id null": ([valid], {"dispatch_id": None}),
        "no recorded dispatch": ([], {}),
    }


def apply_overrides(entry: dict, overrides: dict) -> dict:
    entry = dict(entry)
    for key, value in overrides.items():
        if value == "__drop__":
            entry.pop(key, None)
        else:
            entry[key] = value
    return entry


class AttemptedBindingFailureTests(unittest.TestCase):
    """A failed or ambiguous attempted binding is never primary and keeps known restrictions."""

    def assert_held(self, result: dict, name: str, case: str = "") -> None:
        # Behavior first, then the reported binding state.
        subject = lane(result, name)
        self.assertNotEqual(subject["synthesis_use"], "primary")
        self.assertEqual(result["status"], "blocked")
        if case.startswith("input dispatch_id"):
            # Round 8: the subject may name the control's dispatch, so the control's binding does not hold
            # either (it used to stay primary).
            self.assertEqual(result["primary_input_count"], 0)
            self.assertIn(WILDCARD_INPUT_REASON, lane(result, "opus")["dispatch_binding"]["reasons"])
        else:
            self.assertEqual(result["primary_input_count"], 1)
            self.assertEqual(lane(result, "opus")["synthesis_use"], "primary")
        self.assertFalse(subject["dispatch_binding"]["bound"])
        self.assertTrue(subject["dispatch_binding"]["reasons"])
        self.assertEqual(subject["dispatch_binding"]["state"], "failed")

    def test_valid_paths_are_ready_or_restricted(self) -> None:
        # Controls for the cases below: each subject is primary (or, for
        # Gemini, salvage-only) when its binding is valid.
        valid = run([accepted_unheld("subject", "d-subject"), control_input()],
                    [CONTROL, dispatch("d-subject", "codex_architecture_critic")])
        self.assertEqual(valid["status"], "ready")
        self.assertTrue(lane(valid, "subject")["dispatch_binding"]["bound"])
        accepted = run([recommended_primary("subject", "d-subject"), control_input()],
                       [CONTROL, dispatch("d-subject", "codex_architecture_critic")],
                       [acceptance("adj-subject", "d-subject")])
        self.assertEqual(lane(accepted, "subject")["synthesis_use"], "primary")
        self.assertEqual(accepted["status"], "ready")
        gemini = run([accepted_unheld("subject", "d-subject"), control_input()],
                     [CONTROL, dispatch("d-subject", "gemini_architecture_critic")])
        self.assertEqual(lane(gemini, "subject")["synthesis_use"], "salvage-only")
        self.assertEqual(gemini["status"], "blocked")

    def test_failed_gemini_binding_is_not_primary(self) -> None:
        # Reviewer reproduction: provider_family [], version 1.0 or a
        # duplicated dispatch made an accepted Gemini return primary.
        for name, (records, overrides) in failed_bindings("gemini_architecture_critic").items():
            with self.subTest(case=name):
                entry = apply_overrides(accepted_unheld("gemini", "d-subject"), overrides)
                result = run([entry, control_input()], [CONTROL, *records])
                self.assert_held(result, "gemini", name)
                self.assertIsNotNone(lane(result, "gemini")["primary_use_withheld"])

    def test_failed_binding_of_an_accepted_unheld_return_is_not_primary(self) -> None:
        for shape, build, adjudications in (
            ("disposition primary", accepted_unheld, []),
            ("recommended primary with a bound acceptance", recommended_primary, [acceptance("adj-subject", "d-subject")]),
        ):
            for name, (records, overrides) in failed_bindings("codex_architecture_critic").items():
                with self.subTest(shape=shape, case=name):
                    entry = apply_overrides(build("subject", "d-subject"), overrides)
                    result = run([entry, control_input()], [CONTROL, *records], adjudications)
                    self.assert_held(result, "subject", name)

    def test_shared_dispatch_id_is_a_failed_binding(self) -> None:
        records = [CONTROL, dispatch("d-subject", "codex_architecture_critic")]
        result = run([accepted_unheld("subject", "d-subject"), accepted_unheld("copy", "d-subject"), control_input()],
                     records)
        for name in ("subject", "copy"):
            self.assertNotEqual(lane(result, name)["synthesis_use"], "primary")
        self.assertEqual(result["primary_input_count"], 1)
        self.assertEqual(result["status"], "blocked")
        for name in ("subject", "copy"):
            self.assertEqual(lane(result, name)["dispatch_binding"]["state"], "failed")

    def test_dispatch_rejection_is_reported_alongside_the_hold(self) -> None:
        records = [CONTROL, dispatch("d-subject", "gemini_architecture_critic", provider_family=[])]
        result = run([accepted_unheld("gemini", "d-subject"), control_input()], records)
        self.assertEqual([item["index"] for item in rejections(result, "dispatch_records")], [1])
        self.assertEqual(lane(result, "gemini")["synthesis_use"], "open-risk")
        self.assertIn("binding", lane(result, "gemini")["primary_use_withheld"])

    def test_input_without_binding_metadata_keeps_legacy_treatment(self) -> None:
        result = run([accepted_unheld("legacy", None), control_input()], [CONTROL])
        legacy = lane(result, "legacy")
        self.assertEqual(legacy["synthesis_use"], "primary")
        self.assertEqual(result["status"], "ready")
        self.assertEqual(legacy["dispatch_binding"]["state"], "absent")
        self.assertFalse(legacy["dispatch_binding"]["attempted"])


class AdjudicationResolutionFailureTests(unittest.TestCase):
    """Invalid or ambiguous resolution holds the return and keeps restrictive decisions."""

    records = [CONTROL, dispatch("d-subject", "codex_architecture_critic")]

    def resolve(self, entry: dict, adjudications: list) -> dict:
        return run([entry, control_input()], self.records, adjudications)

    def extra_records(self) -> dict:
        return {
            "decision is an array": adjudication("adj-extra", "d-subject", decision=[], evidence=[]),
            "decision is an object": adjudication("adj-extra", "d-subject", decision={}, evidence=[]),
            "decision unknown": adjudication("adj-extra", "d-subject", decision="approved", evidence=[]),
            "version is 1.0": acceptance("adj-extra", "d-subject", version=1.0),
            "rationale missing": acceptance("adj-extra", "d-subject", rationale=""),
            "authority unconfigured": acceptance("adj-extra", "d-subject", authority={"rule": "architect-override"}),
            "scope is an array": acceptance("adj-extra", "d-subject", scope=[SCOPE]),
            "valid rejection": adjudication("adj-extra", "d-subject", decision="rejected", evidence=[]),
            "valid acceptance": acceptance("adj-extra", "d-subject"),
        }

    def test_valid_paths(self) -> None:
        quarantine = adjudication("adj-q", "d-subject", decision="quarantined", evidence=[])
        result = self.resolve(accepted_unheld("subject", "d-subject"), [quarantine])
        self.assertEqual(lane(result, "subject")["synthesis_use"], "quarantine")
        self.assertEqual(result["status"], "blocked")
        accepted = self.resolve(recommended_primary("subject", "d-subject"), [acceptance("adj-a", "d-subject")])
        self.assertEqual(lane(accepted, "subject")["synthesis_use"], "primary")
        self.assertEqual(accepted["status"], "ready")

    def test_invalid_or_ambiguous_resolution_keeps_a_quarantine(self) -> None:
        # Reviewer reproduction: a second current record with decision []
        # (invalid) or a valid rejection (ambiguous) discarded the quarantine.
        quarantine = adjudication("adj-q", "d-subject", decision="quarantined", evidence=[])
        for name, extra in self.extra_records().items():
            with self.subTest(case=name):
                result = self.resolve(accepted_unheld("subject", "d-subject"), [quarantine, extra])
                subject = lane(result, "subject")
                self.assertEqual(subject["synthesis_use"], "quarantine")
                self.assertEqual(result["primary_input_count"], 1)
                self.assertEqual(result["status"], "blocked")
                self.assertIn(subject["adjudication"]["state"], {"invalid", "ambiguous"})
                self.assertIn("quarantined", subject["pending_restrictions"])

    # Round 7: a record whose decision cannot be read may be a quarantine.
    UNREADABLE_DECISIONS = ("decision is an array", "decision is an object", "decision unknown")

    def test_invalid_or_ambiguous_resolution_keeps_a_rejection(self) -> None:
        rejection = adjudication("adj-r", "d-subject", decision="rejected", evidence=[])
        for name, extra in self.extra_records().items():
            if name == "valid rejection":
                continue
            with self.subTest(case=name):
                result = self.resolve(accepted_unheld("subject", "d-subject"), [rejection, extra])
                subject = lane(result, "subject")
                self.assertIn(subject["adjudication"]["state"], {"invalid", "ambiguous"})
                self.assertIn("rejected", subject["pending_restrictions"])
                self.assertEqual(subject["synthesis_use"],
                                 "quarantine" if name in self.UNREADABLE_DECISIONS else "reject")
                self.assertIsNone(subject["use_hold_resolved_by"])
                self.assertEqual(result["status"], "blocked")

    def test_invalid_or_ambiguous_resolution_holds_an_accepted_unheld_return(self) -> None:
        cases = {name: record for name, record in self.extra_records().items() if name != "valid rejection"}
        # A disposition-primary return is held (open-risk); a recommended-primary
        # return stays unauthorized (unknown), which blocks on its own.
        for shape, build, expected in (("disposition primary", accepted_unheld, "open-risk"),
                                       ("recommended primary", recommended_primary, "unknown")):
            for name, extra in cases.items():
                with self.subTest(shape=shape, case=name):
                    result = self.resolve(build("subject", "d-subject"), [acceptance("adj-a", "d-subject"), extra])
                    subject = lane(result, "subject")
                    self.assertIn(subject["adjudication"]["state"], {"invalid", "ambiguous"})
                    self.assertFalse(subject["adjudication"]["authorizes_requested_use"])
                    if name in self.UNREADABLE_DECISIONS:
                        self.assertEqual(subject["synthesis_use"], "quarantine")
                        self.assertTrue(subject["quarantine_in_force"])
                        continue
                    self.assertEqual(subject["synthesis_use"], expected)
                    if expected == "open-risk":
                        self.assertIn("adjudication resolution", subject["primary_use_withheld"])
                    self.assertEqual(result["status"], "blocked")
            for name, record in cases.items():
                if name == "valid acceptance":
                    continue
                with self.subTest(shape=shape, case="only " + name):
                    result = self.resolve(build("subject", "d-subject"), [record])
                    self.assertNotEqual(lane(result, "subject")["synthesis_use"], "primary")
                    self.assertEqual(result["status"], "blocked")

    def test_a_malformed_restrictive_record_still_restricts(self) -> None:
        for decision, expected in (("quarantined", "quarantine"), ("rejected", "reject"), ("Quarantined", "quarantine")):
            for name, overrides in {
                "candidate missing": {"candidate": None},
                "candidate null": {"candidate": None},
                "candidate unreadable": {"candidate": []},
                "rationale missing": {"rationale": ""},
                "version is 1.0": {"version": 1.0},
                "authority missing": {"authority": None},
                "finding ids malformed": {"finding_ids": [[]]},
            }.items():
                with self.subTest(decision=decision, case=name):
                    record = adjudication("adj-x", "d-subject", decision=decision, evidence=[], **overrides)
                    if name == "candidate missing":
                        record.pop("candidate")
                    result = self.resolve(accepted_unheld("subject", "d-subject"), [record])
                    self.assertEqual(lane(result, "subject")["adjudication"]["state"], "invalid")
                    self.assertEqual(lane(result, "subject")["synthesis_use"], expected)
                    self.assertEqual(result["status"], "blocked")

    def test_failed_binding_keeps_a_restrictive_decision(self) -> None:
        quarantine = adjudication("adj-q", "d-subject", decision="quarantined", evidence=[])
        for name, (records, overrides) in failed_bindings("codex_architecture_critic").items():
            if "dispatch_id" in overrides:
                continue  # no record can name an input that names no usable dispatch_id
            with self.subTest(case=name):
                entry = apply_overrides(accepted_unheld("subject", "d-subject"), overrides)
                record = {**quarantine, "return_sha256": entry["return_sha256"]} if name == "return digest differs" else quarantine
                result = run([entry, control_input()], [CONTROL, *records], [record])
                self.assertEqual(lane(result, "subject")["adjudication"]["state"], "unbound")
                self.assertEqual(lane(result, "subject")["synthesis_use"], "quarantine")

    def test_provable_history_does_not_restrict(self) -> None:
        for overrides in ({"candidate": OTHER_CANDIDATE}, {"scope": "bead:another-task"},
                          {"return_sha256": sha("an earlier return")}):
            with self.subTest(history=overrides):
                record = adjudication("adj-old", "d-subject", decision="quarantined", evidence=[], **overrides)
                result = self.resolve(accepted_unheld("subject", "d-subject"), [record])
                subject = lane(result, "subject")
                self.assertEqual(subject["synthesis_use"], "primary")
                self.assertEqual(result["status"], "ready")
                self.assertEqual(subject["adjudication"]["historical_adjudication_ids"], ["adj-old"])
                self.assertEqual(subject["pending_restrictions"], [])

    def test_adjudications_that_are_not_a_list_hold_every_input(self) -> None:
        # Round 7: nothing in a non-list value can be read, so it may hold a
        # refusal for any input, a legacy one included (round 3 exempted
        # legacy inputs, which let the value drop a refusal).
        result = run([recommended_primary("subject", "d-subject"), control_input(), accepted_unheld("legacy", None)],
                     self.records, {"adj-a": acceptance("adj-a", "d-subject")})
        for name in ("subject", "opus", "legacy"):
            self.assertEqual(lane(result, name)["adjudication"]["state"], "invalid")
            self.assertEqual(lane(result, name)["synthesis_use"], "quarantine")
            self.assertEqual(lane(result, name)["pending_restrictions"], ["quarantined", "rejected"])
        self.assertIn("adjudications is not a list, so the records it holds are unresolved", result["blocked_reasons"])
        self.assertEqual(result["status"], "blocked")


class MalformedHoldTests(unittest.TestCase):
    """Missing hold fields are absent; null or malformed hold fields hold the input and cannot be cleared."""

    records = [CONTROL, dispatch("d-subject", "codex_architecture_critic")]
    MALFORMED_FLAGS = {
        "null": None, "empty string": "", "blank string": " ", "none string": "none", "unknown string": "pending",
        "array": [True], "empty array": [], "object": {"value": True}, "float": 0.5, "float zero": 0.0, "float one": 1.0, "integer 2": 2,
    }

    def test_null_hold_flag_does_not_lift_a_peer_review_hold(self) -> None:
        # Reviewer reproduction: implementation_blocked true -> null turned
        # open-risk/blocked into primary/ready without diagnostics.
        for name, value in {"true": True, **self.MALFORMED_FLAGS}.items():
            with self.subTest(flag=name):
                entry = recommended_primary("subject", "d-subject", implementation_blocked=value,
                                            hold_reasons=["peer-review-pending"])
                result = run([entry, control_input()], self.records,
                             [acceptance("adj-a", "d-subject", finding_ids=["peer-review-pending"],
                                         supporting_evidence=[{"artifact": "log", "artifact_type": "validation-log",
                                                               "sha256": sha("log"), "finding_ids": ["peer-review-pending"]}])])
                subject = lane(result, "subject")
                self.assertEqual(subject["synthesis_use"], "open-risk")
                self.assertTrue(subject["implementation_blocked"])
                self.assertEqual(result["status"], "blocked")
                if name != "true":
                    self.assertTrue(subject["hold_flag_malformed"])
                    self.assertTrue(any("implementation_blocked" in error for error in subject["input_errors"]))
                    self.assertEqual([item["index"] for item in rejections(result, "inputs")], [0])

    def test_malformed_hold_flag_cannot_be_cleared_by_acceptance(self) -> None:
        # The same flags next to a tripwire reason that a bound acceptance
        # would clear if the flag were a valid true.
        for name, value in self.MALFORMED_FLAGS.items():
            with self.subTest(flag=name):
                entry = recommended_primary("subject", "d-subject", implementation_blocked=value, hold_reasons=[TRIPWIRE])
                result = run([entry, control_input()], self.records, [adjudication("adj-a", "d-subject")])
                subject = lane(result, "subject")
                self.assertEqual(subject["adjudication"]["state"], "applied")
                self.assertFalse(subject["adjudication"]["authorizes_requested_use"])
                self.assertIn("hold flag is malformed", subject["adjudication"]["not_authorized_reason"])
                self.assertEqual(subject["synthesis_use"], "open-risk")
                self.assertEqual(result["status"], "blocked")
        for flag in (True, 1):
            with self.subTest(valid_flag=flag, type=type(flag).__name__):
                valid = run([recommended_primary("subject", "d-subject", implementation_blocked=flag,
                                                  hold_reasons=[TRIPWIRE]), control_input()],
                            self.records, [adjudication("adj-a", "d-subject")])
                self.assertEqual(lane(valid, "subject")["synthesis_use"], "primary")

    def test_unheld_malformed_hold_input_family(self) -> None:
        rows = (
            ("test_malformed_hold_flag_holds_an_accepted_unheld_return", "implementation_blocked",
             self.MALFORMED_FLAGS, ({},),
             (("disposition primary", accepted_unheld, []),
              ("recommended primary with a bound acceptance", recommended_primary, [acceptance("adj-a", "d-subject")])),
             False),
            ("test_malformed_hold_reasons_hold_an_accepted_unheld_return", "hold_reasons",
             {"null": None, "number": 7, "string": TRIPWIRE, "object": {TRIPWIRE: True},
              "nested array": [[TRIPWIRE]], "mixed": [TRIPWIRE, 7]},
             ({}, {"implementation_blocked": False}, {"implementation_blocked": True}),
             (("recommended primary", recommended_primary, [adjudication("adj-a", "d-subject")]),), True),
        )
        for row_id, field, values, flag_options, shapes, check_reasons in rows:
            for name, value in values.items():
                for flags in flag_options:
                    for shape, build, adjudications in shapes:
                        with self.subTest(row=row_id, value=name, flag=flags, shape=shape):
                            entry = build("subject", "d-subject", **{field: copy.deepcopy(value)}, **flags)
                            result = run([entry, control_input()], self.records, copy.deepcopy(adjudications))
                            subject = lane(result, "subject")
                            self.assertEqual(subject["synthesis_use"], "open-risk")
                            self.assertEqual(result["status"], "blocked")
                            if check_reasons:
                                self.assertTrue(subject["implementation_blocked"])
                                self.assertTrue(subject["hold_reasons_malformed"])


    def test_missing_and_valid_hold_fields_keep_their_meaning(self) -> None:
        for name, flag in {"missing": {}, "false": {"implementation_blocked": False}, "zero": {"implementation_blocked": 0},
                           "false string": {"implementation_blocked": "false"}, "empty reasons": {"hold_reasons": []}}.items():
            with self.subTest(case=name):
                entry = recommended_primary("subject", "d-subject", **flag)
                result = run([entry, control_input()], self.records, [acceptance("adj-a", "d-subject")])
                subject = lane(result, "subject")
                self.assertEqual(subject["synthesis_use"], "primary")
                self.assertEqual(result["status"], "ready")
                self.assertFalse(subject["implementation_blocked"])
                self.assertEqual(subject["input_errors"], [])
                self.assertFalse(subject["hold_flag_malformed"])


class SweepFailureNotAbsenceTests(unittest.TestCase):
    """Same class found by the round-3 fuzz probe: a failed value is never read as an absent one."""

    records = [CONTROL, dispatch("d-subject", "codex_architecture_critic")]

    def test_malformed_disposition_is_not_promoted_by_a_bound_acceptance(self) -> None:
        for name, value in {"null": None, "empty string": "", "blank string": " ", "empty array": [],
                            "empty object": {}, "false": False}.items():
            with self.subTest(disposition=name):
                entry = recommended_primary("subject", "d-subject", disposition=value)
                result = run([entry, control_input()], self.records, [acceptance("adj-a", "d-subject")])
                subject = lane(result, "subject")
                self.assertNotEqual(subject["synthesis_use"], "primary")
                self.assertEqual(result["status"], "blocked")
                self.assertTrue(any("disposition" in error for error in subject["input_errors"]))

    def test_partial_or_open_risk_disposition_is_not_promoted_by_a_bound_acceptance(self) -> None:
        for disposition, expected in (("missing", "partial-only"), ("empty", "partial-only"),
                                      ("timed-out", "partial-only"), ("deferred", "open-risk"),
                                      ("needs-investigation", "open-risk"), (None, "partial-only")):
                # An absent disposition reads as "missing" and, since round 7,
                # is also unresolved (blocked with a possible quarantine).
            with self.subTest(disposition=disposition):
                entry = recommended_primary("subject", "d-subject", disposition=disposition)
                if disposition is None:
                    del entry["disposition"]  # absent reads as "missing"
                result = run([entry, control_input()], self.records, [acceptance("adj-a", "d-subject")])
                self.assertEqual(lane(result, "subject")["synthesis_use"], expected)
                self.assertEqual(result["status"], "blocked")

    def test_hold_reasons_without_the_flag_hold_the_input(self) -> None:
        for flag in ({}, {"implementation_blocked": False}, {"implementation_blocked": "false"}):
            for reasons in ([TRIPWIRE], ["peer-review-pending"]):
                with self.subTest(flag=flag, reasons=reasons):
                    entry = recommended_primary("subject", "d-subject", hold_reasons=reasons, **flag)
                    record = adjudication("adj-a", "d-subject", findings=tuple(reasons))
                    result = run([entry, control_input()], self.records, [record])
                    subject = lane(result, "subject")
                    self.assertEqual(subject["synthesis_use"], "open-risk")
                    self.assertEqual(result["status"], "blocked")
                    self.assertTrue(subject["implementation_blocked"])
                    self.assertFalse(subject["adjudication"]["authorizes_requested_use"])
                    self.assertTrue(any("hold_reasons are recorded" in error for error in subject["input_errors"]))

    def test_restrictive_record_without_a_readable_dispatch_id_blocks(self) -> None:
        quarantine = adjudication("adj-q", "d-subject", decision="quarantined", evidence=[])
        for name, value in {"null": None, "empty string": "", "array": ["d-subject"], "object": {"id": "d-subject"},
                            "missing": "__drop__"}.items():
            with self.subTest(dispatch_id=name):
                record = dict(quarantine)
                if value == "__drop__":
                    del record["dispatch_id"]
                else:
                    record["dispatch_id"] = value
                result = run([accepted_unheld("subject", "d-subject"), control_input()], self.records, [record])
                self.assertEqual(result["status"], "blocked")
                self.assertTrue(any("restrictive decision" in reason for reason in result["blocked_reasons"]))
        # A refusal for a dispatch that is not among the inputs names its target and does not block.
        other = run([accepted_unheld("subject", "d-subject"), control_input()], self.records,
                    [adjudication("adj-q", "d-elsewhere", decision="quarantined", evidence=[])])
        self.assertEqual(other["status"], "ready")


class UnderlyingBrokerFlagTests(unittest.TestCase):
    executors = {"executors": {"fusion": {"provider_key": "broker"}, "direct": {"provider_key": "anthropic_api"}}}

    def providers(self, flag: object) -> dict:
        return {
            "providers": {
                "broker": {"family": "openrouter", "broker": True, "underlying_providers": ["anthropic_api"]},
                "anthropic_api": {"family": "anthropic", "broker": flag},
            }
        }

    def test_non_boolean_underlying_broker_flag_leaves_provenance_unknown(self) -> None:
        from cwo_core.adjudication import dispatch_provenance

        for flag in ("true", "false", "", 1, 0, None, [], {}, [True]):
            with self.subTest(flag=flag):
                observed = dispatch_provenance(
                    dispatch("d", "fusion", underlying_provider_key="anthropic_api"),
                    executor_registry=self.executors, provider_registry=self.providers(flag),
                )
                self.assertFalse(observed["known"])
                self.assertIsNone(observed["provider_family"])
                self.assertIn("broker flag is not a boolean", " ".join(observed["reasons"]))
                # Selecting the same provider directly is also unknown.
                direct = dispatch_provenance(
                    dispatch("d", "direct"), executor_registry=self.executors, provider_registry=self.providers(flag)
                )
                self.assertFalse(direct["known"])
        for flag in (False, "__absent__"):
            with self.subTest(flag=flag):
                providers = self.providers(flag)
                if flag == "__absent__":
                    del providers["providers"]["anthropic_api"]["broker"]
                observed = dispatch_provenance(
                    dispatch("d", "fusion", underlying_provider_key="anthropic_api"),
                    executor_registry=self.executors, provider_registry=providers,
                )
                self.assertTrue(observed["known"])
                self.assertEqual(observed["provider_family"], "anthropic")

    def test_integrated_broker_return_with_a_non_boolean_underlying_flag_is_not_primary(self) -> None:
        import cwo_core.adjudication as adjudication_module

        real = adjudication_module.load_policy
        claim = {"claim_id": "auth:jwt", "category": "auth", "key": "jwt", "value": "RS256 only"}
        for flag in ("true", 1, None):
            with self.subTest(flag=flag):
                fake = {
                    "executor-registry": {"executors": {"fusion": {"provider_key": "broker"},
                                                        "direct_openai": {"provider_key": "openai_api"}}},
                    "provider-registry": {"providers": {
                        "broker": {"family": "openrouter", "broker": True, "underlying_providers": ["anthropic_api"]},
                        "anthropic_api": {"family": "anthropic", "broker": flag},
                        "openai_api": {"family": "openai"},
                    }},
                }

                def load(name: str) -> dict:
                    return copy.deepcopy(fake[name]) if name in fake else real(name)

                records = [dispatch("d-broker", "fusion", underlying_provider_key="anthropic_api"),
                           dispatch("d-openai", "direct_openai")]
                inputs = [returned("broker", "d-broker", zero_trust_claims=[claim]),
                          returned("openai", "d-openai", zero_trust_claims=[claim])]
                with mock.patch.object(adjudication_module, "load_policy", side_effect=load):
                    result = run(inputs, records, zero_trust_required=True)
                broker = lane(result, "broker")
                self.assertTrue(broker["dispatch_binding"]["bound"])
                self.assertFalse(broker["dispatch_binding"]["provenance_known"])
                self.assertNotEqual(broker["synthesis_use"], "primary")
                self.assertEqual(result["zero_trust_consensus"]["independent_trust_domains"], ["openai"])
                self.assertEqual(result["status"], "blocked")


class ExternalInputQuarantineTests(unittest.TestCase):
    """An adjudication quarantine of an external input reaches the external-input block.

    Two internal primaries satisfy minimum_usable_inputs in every case, so
    insufficient-input blocking cannot mask the result.
    """

    records = [CONTROL, dispatch("d-chatgpt", "chatgpt_pro_browser_master_reviewer"),
               dispatch("d-ext", "codex_architecture_critic")]
    quarantine = adjudication("adj-q", "d-ext", decision="quarantined", evidence=[])
    malformed_flags = ("false", "true", "", 0, 1, None, [], {})

    def internal(self) -> list[dict]:
        return [returned("opus", "d-opus", external=False), returned("chatgpt", "d-chatgpt", external=False)]

    def external(self, build=accepted_unheld, flag: object = True, **fields: object) -> dict:
        entry = build("ext", "d-ext", **fields)
        if flag != "__absent__":
            entry["external"] = flag
        return entry

    def assert_external_block(self, result: dict) -> None:
        # Behavior first: the internal primaries remain, the external input is
        # not primary, and the block is the external-input block.
        self.assertEqual(result["primary_input_count"], 2)
        self.assertNotEqual(lane(result, "ext")["synthesis_use"], "primary")
        self.assertIn(EXTERNAL_BLOCK, result["blocked_reasons"])
        self.assertNotIn(MINIMUM_BLOCK, result["blocked_reasons"])
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(lane(result, "ext")["quarantine_in_force"])

    def test_valid_paths(self) -> None:
        # Controls: the external input is primary and the result ready; an
        # evaluator or boundary quarantine of the same input blocks.
        for flag in (True, "__absent__"):
            with self.subTest(external=flag):
                result = run([*self.internal(), self.external(flag=flag)], self.records)
                self.assertEqual(result["primary_input_count"], 3)
                self.assertEqual(result["status"], "ready")
                self.assertFalse(lane(result, "ext")["quarantine_in_force"])
                accepted = run([*self.internal(), self.external(recommended_primary, flag)], self.records,
                               [acceptance("adj-a", "d-ext")])
                self.assertEqual(lane(accepted, "ext")["synthesis_use"], "primary")
                self.assertEqual(accepted["status"], "ready")
                for fields in ({"disposition": "quarantined"}, {"boundary_status": "boundary-tainted"},
                               {"boundary_taint_status": ["tainted"]}):
                    with self.subTest(external=flag, fields=fields):
                        result = run([*self.internal(), self.external(flag=flag, **fields)], self.records)
                        self.assertEqual(lane(result, "ext")["synthesis_use"], "quarantine")
                        self.assert_external_block(result)

    def test_applied_adjudication_quarantine_blocks(self) -> None:
        # Reviewer reproduction: the same quarantine applied by a bound
        # adjudication gave partial, blocked false.
        for flag in (True, "__absent__"):
            for shape, build in (("disposition primary", accepted_unheld), ("recommended primary", recommended_primary),
                                 ("tripwire held", tripwire_held)):
                with self.subTest(external=flag, shape=shape):
                    result = run([*self.internal(), self.external(build, flag)], self.records, [self.quarantine])
                    self.assertEqual(lane(result, "ext")["synthesis_use"], "quarantine")
                    self.assert_external_block(result)
                    self.assertEqual(lane(result, "ext")["adjudication"]["state"], "applied")
                    self.assertEqual(lane(result, "ext")["adjudication"]["decision"], "quarantined")

    def test_pending_quarantine_after_invalid_or_ambiguous_resolution_blocks(self) -> None:
        extras = {
            "decision is an array": adjudication("adj-x", "d-ext", decision=[], evidence=[]),
            "version is 1.0": acceptance("adj-x", "d-ext", version=1.0),
            "authority unconfigured": acceptance("adj-x", "d-ext", authority={"rule": "architect-override"}),
            "valid rejection": adjudication("adj-x", "d-ext", decision="rejected", evidence=[]),
            "valid acceptance": acceptance("adj-x", "d-ext"),
        }
        cases = {name: [self.quarantine, extra] for name, extra in extras.items()}
        cases["lone malformed quarantine"] = [{**self.quarantine, "rationale": ""}]
        cases["lone quarantine with version 1.0"] = [{**self.quarantine, "version": 1.0}]
        for flag in (True, "__absent__"):
            for shape, build in (("disposition primary", accepted_unheld), ("tripwire held", tripwire_held)):
                for name, adjudications in cases.items():
                    with self.subTest(external=flag, shape=shape, case=name):
                        result = run([*self.internal(), self.external(build, flag)], self.records, adjudications)
                        ext = lane(result, "ext")
                        # A held return stays open-risk; the quarantine is still in force.
                        self.assertEqual(ext["synthesis_use"], "open-risk" if shape == "tripwire held" else "quarantine")
                        self.assert_external_block(result)
                        self.assertIn(ext["adjudication"]["state"], {"invalid", "ambiguous"})
                        self.assertIn("quarantined", ext["pending_restrictions"])

    def test_malformed_external_flag_is_read_both_ways(self) -> None:
        pending = [self.quarantine, adjudication("adj-x", "d-ext", decision=[], evidence=[])]
        for value in self.malformed_flags:
            for name, adjudications in (("applied", [self.quarantine]), ("pending", pending)):
                with self.subTest(reading="read as external", quarantine=name, external=value):
                    # The quarantined input is the only external one if the
                    # flag reads true.
                    result = run([*self.internal(), self.external(flag=value)], self.records, adjudications)
                    self.assertEqual(lane(result, "ext")["synthesis_use"], "quarantine")
                    self.assert_external_block(result)
                    self.assertEqual([item["index"] for item in rejections(result, "inputs")], [2])
                with self.subTest(reading="read as internal", quarantine=name, external=value):
                    # A clean input with a malformed flag is not external if
                    # the flag reads false, so the quarantined external input
                    # is the only external one.
                    result = run([*self.internal(), self.external(), returned("other", None, external=value)],
                                 self.records, adjudications)
                    self.assertEqual(result["primary_input_count"], 3)
                    self.assertIn(EXTERNAL_BLOCK, result["blocked_reasons"])
                    self.assertEqual(result["status"], "blocked")

    def test_an_external_input_outside_any_quarantine_lifts_the_block(self) -> None:
        # Negative controls: the predicate widens only for a quarantine in force.
        history = adjudication("adj-old", "d-ext", decision="quarantined", evidence=[], candidate=OTHER_CANDIDATE)
        result = run([*self.internal(), self.external()], self.records, [history])
        self.assertEqual(lane(result, "ext")["synthesis_use"], "primary")
        self.assertFalse(lane(result, "ext")["quarantine_in_force"])
        self.assertEqual(result["status"], "ready")
        result = run([*self.internal(), self.external(), returned("other", None, external=True)],
                     self.records, [self.quarantine])
        self.assertEqual(lane(result, "ext")["synthesis_use"], "quarantine")
        self.assertNotIn(EXTERNAL_BLOCK, result["blocked_reasons"])
        self.assertEqual(result["status"], "partial")
        for value in self.malformed_flags:
            with self.subTest(external=value):
                result = run([*self.internal(), returned("other", None, external=value)], self.records)
                self.assertNotIn(EXTERNAL_BLOCK, result["blocked_reasons"])


class NegativePathSideEffectTests(unittest.TestCase):
    """Malformed, rejected and ambiguous cases change nothing outside the result."""

    def cases(self) -> dict:
        records = [CONTROL, dispatch("d-subject", "codex_architecture_critic")]
        quarantine = adjudication("adj-q", "d-subject", decision="quarantined", evidence=[])
        return {
            "malformed dispatch": (
                [accepted_unheld("subject", "d-subject"), control_input()],
                [CONTROL, dispatch("d-subject", "gemini_architecture_critic", provider_family=[])], [], "open-risk"),
            "duplicated dispatch": (
                [accepted_unheld("subject", "d-subject"), control_input()],
                [*records, dispatch("d-subject", "codex_architecture_critic")], [], "open-risk"),
            "invalid adjudication beside a quarantine": (
                [accepted_unheld("subject", "d-subject"), control_input()], records,
                [quarantine, adjudication("adj-x", "d-subject", decision=[], evidence=[])], "quarantine"),
            "ambiguous adjudication beside a quarantine": (
                [accepted_unheld("subject", "d-subject"), control_input()], records,
                [quarantine, adjudication("adj-r", "d-subject", decision="rejected", evidence=[])], "quarantine"),
            "ambiguous acceptances": (
                [recommended_primary("subject", "d-subject"), control_input()], records,
                [acceptance("adj-1", "d-subject"), acceptance("adj-2", "d-subject")], "unknown"),
            "bound rejection": (
                [recommended_primary("subject", "d-subject"), control_input()], records,
                [adjudication("adj-r", "d-subject", decision="rejected", evidence=[])], "reject"),
            "null hold flag": (
                [recommended_primary("subject", "d-subject", implementation_blocked=None,
                                     hold_reasons=["peer-review-pending"]), control_input()],
                records, [acceptance("adj-a", "d-subject")], "open-risk"),
            "malformed hold flag with a clearable reason": (
                [recommended_primary("subject", "d-subject", implementation_blocked=[True], hold_reasons=[TRIPWIRE]),
                 control_input()], records, [adjudication("adj-a", "d-subject")], "open-risk"),
            "null hold reasons": (
                [recommended_primary("subject", "d-subject", hold_reasons=None), control_input()],
                records, [acceptance("adj-a", "d-subject")], "open-risk"),
            "non-list adjudications": (
                [recommended_primary("subject", "d-subject"), control_input()], records,
                {"adj-a": acceptance("adj-a", "d-subject")}, "quarantine"),
            "ambiguous acceptances of an accepted return": (
                [accepted_unheld("subject", "d-subject"), control_input()], records,
                [acceptance("adj-1", "d-subject"), acceptance("adj-2", "d-subject")], "open-risk"),
        }

    claim = {"claim_id": "auth:jwt", "category": "auth", "key": "jwt", "value": "RS256 only"}

    def with_claims(self, inputs: list) -> list:
        # Comparable claims on every input, so required consensus has no
        # blocking cause of its own while the subject stays primary.
        return [{**entry, "zero_trust_claims": [self.claim]} if isinstance(entry, dict) else entry for entry in inputs]

    def expected_blocked_reasons(self, expected_use: str, primaries: int, name: str = "") -> set:
        # The intended cause: the subject leaves the primary inputs, so fewer
        # primaries and trust domains remain. An unauthorized recommended
        # primary is also an unknown use.
        reasons = {
            MINIMUM_BLOCK,
            f"zero-trust consensus requires 2 independent trust domains; observed {primaries}",
            "zero-trust consensus requires comparable claims across independent trust domains"
            if primaries
            else "zero-trust consensus requires explicit zero_trust_claims on accepted primary inputs",
        }
        if expected_use == "unknown":
            reasons.add("one or more inputs have unknown evaluator dispositions")
        # Round 7: an input taken out of primary use by malformed or unresolved
        # data keeps its claims unresolved instead of dropping them; a bound
        # rejection is a well-formed decision.
        if name != "bound rejection":
            reasons.add(
                f"zero-trust consensus is unresolved: subject: the input is {expected_use} because of malformed "
                "or unresolved data, so whether its zero_trust_claims count is unresolved")
        # Round 7: a recommended primary use that no applied adjudication
        # authorizes stays unresolved when a hold or a pending refusal sets
        # the final use (it used to block only when the use was "unknown").
        if name in ("null hold flag", "malformed hold flag with a clearable reason", "null hold reasons",
                    "non-list adjudications"):
            reasons.add(UNRESOLVED_REQUEST_BLOCK)
        if name == "non-list adjudications":
            reasons.add("zero-trust consensus is unresolved: opus: the input is quarantine because of malformed "
                        "or unresolved data, so whether its zero_trust_claims count is unresolved")
            reasons.add("adjudications is not a list, so the records it holds are unresolved")
            reasons.add(EXTERNAL_BLOCK)
        return reasons

    def test_valid_paths_are_ready(self) -> None:
        # Positive controls with the same claims: each subject shape is primary
        # and the result is ready under required consensus.
        records = [CONTROL, dispatch("d-subject", "codex_architecture_critic")]
        for shape, inputs, adjudications in (
            ("disposition primary", [accepted_unheld("subject", "d-subject"), control_input()], []),
            ("recommended primary with a bound acceptance",
             [recommended_primary("subject", "d-subject"), control_input()], [acceptance("adj-a", "d-subject")]),
            ("tripwire held and cleared",
             [tripwire_held("subject", "d-subject"), control_input()], [adjudication("adj-a", "d-subject")]),
        ):
            with self.subTest(shape=shape):
                result = run(self.with_claims(inputs), records, adjudications, zero_trust_required=True)
                self.assertEqual(lane(result, "subject")["synthesis_use"], "primary")
                self.assertEqual(result["primary_input_count"], 2)
                self.assertEqual(result["blocked_reasons"], [])
                self.assertEqual(result["status"], "ready")
                self.assertEqual(result["zero_trust_consensus"]["independent_trust_domains"], ["anthropic", "openai"])

    def test_negative_paths_have_no_side_effects_and_keep_restrictions(self) -> None:
        for name, (inputs, records, adjudications, expected) in self.cases().items():
            with self.subTest(case=name):
                inputs = self.with_claims(inputs)
                before = copy.deepcopy((inputs, records, adjudications))
                with mock.patch("subprocess.run", side_effect=AssertionError("subprocess")) as spawn, \
                        mock.patch("subprocess.Popen", side_effect=AssertionError("subprocess")) as popen, \
                        mock.patch("os.system", side_effect=AssertionError("os.system")) as system, \
                        mock.patch("pathlib.Path.write_text", side_effect=AssertionError("write")) as write_text, \
                        mock.patch("pathlib.Path.write_bytes", side_effect=AssertionError("write")) as write_bytes, \
                        mock.patch("cwo_core.audit.record_audit_event", side_effect=AssertionError("audit")) as audit:
                    result = run(inputs, records, adjudications, zero_trust_required=True)
                calls = (spawn.call_count, popen.call_count, system.call_count, write_text.call_count,
                         write_bytes.call_count, audit.call_count)
                self.assertEqual(calls, (0, 0, 0, 0, 0, 0))
                self.assertEqual(before, (inputs, records, adjudications))
                subject = lane(result, "subject")
                self.assertEqual(subject["synthesis_use"], expected)
                self.assertNotIn(subject, result["primary_inputs"])
                # Non-list adjudications also hold the bound control input
                # (accepted in round 3; a possible quarantine since round 7);
                # every other case keeps it primary.
                control_use = "quarantine" if name == "non-list adjudications" else "primary"
                primaries = 1 if control_use == "primary" else 0
                self.assertEqual(lane(result, "opus")["synthesis_use"], control_use)
                self.assertEqual(result["primary_input_count"], primaries)
                self.assertEqual(result["status"], "blocked")
                self.assertEqual(set(result["blocked_reasons"]),
                                 self.expected_blocked_reasons(expected, primaries, name))



# Round 5: a present null is not an absent field, and every quarantine in force
# reaches the external-input block. Every case has two internal primaries
# beside one external lane, so minimum_usable_inputs is met and only the lane
# under test can change the result.
BOUNDARY_FIELDS = ("boundary_taint_status", "boundary_status", "share_boundary_status")
PROVIDER_LABEL_FIELDS = ("provider_camp", "provider_family", "trust_domain")


class ExternalLaneCase(unittest.TestCase):
    records = [CONTROL, dispatch("d-chatgpt", "chatgpt_pro_browser_master_reviewer"),
               dispatch("d-ext", "codex_architecture_critic")]
    malformed_flags = ("false", "true", "", 0, 1, None, [], {})
    claim = {"claim_id": "auth:jwt", "category": "auth", "key": "jwt", "value": "RS256 only",
             "claim_type": "security_assertion", "evidence": "cited the configured allow-list"}

    def internal(self) -> list[dict]:
        return [returned("opus", "d-opus", external=False), returned("chatgpt", "d-chatgpt", external=False)]

    def external(self, build=accepted_unheld, flag: object = True, **fields: object) -> dict:
        entry = apply_overrides(build("ext", "d-ext"), fields)
        if flag != "__absent__":
            entry["external"] = flag
        return entry

    def run_lane(self, entry: dict, adjudications: list | None = None, *extra: dict) -> dict:
        return run([*self.internal(), entry, *extra], self.records, adjudications or [])

    def assert_external_block(self, result: dict) -> None:
        self.assertEqual(result["primary_input_count"], 2)
        self.assertNotEqual(lane(result, "ext")["synthesis_use"], "primary")
        self.assertIn(EXTERNAL_BLOCK, result["blocked_reasons"])
        self.assertNotIn(MINIMUM_BLOCK, result["blocked_reasons"])
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(lane(result, "ext")["quarantine_in_force"])

    def assert_diagnosed(self, result: dict, field: str) -> None:
        rejected = rejections(result, "inputs")
        self.assertEqual([item["index"] for item in rejected], [2])
        self.assertTrue(any(error.startswith(field) for error in rejected[0]["errors"]), rejected[0]["errors"])


class NullBoundaryFieldTests(ExternalLaneCase):
    """A present null or blank boundary field taints the input with a diagnostic."""

    shapes = (
        ("disposition primary", accepted_unheld, []),
        ("recommended primary with a bound acceptance", recommended_primary, [acceptance("adj-a", "d-ext")]),
    )

    def test_valid_paths(self) -> None:
        # Controls: an absent field or a clean status leaves the lane primary.
        for flag in (True, "__absent__"):
            for shape, build, adjudications in self.shapes:
                for field in BOUNDARY_FIELDS:
                    for value in ("__drop__", "clear", "not-applicable"):
                        with self.subTest(external=flag, shape=shape, field=field, value=value):
                            result = self.run_lane(self.external(build, flag, **{field: value}), adjudications)
                            self.assertEqual(lane(result, "ext")["synthesis_use"], "primary")
                            self.assertEqual(result["status"], "ready")
                            self.assertEqual(rejections(result, "inputs"), [])

    def test_null_boundary_field_taints_the_input(self) -> None:
        # Reviewer reproduction: [] blocked and null gave ready, primary.
        for flag in (True, "__absent__"):
            for shape, build, adjudications in self.shapes:
                for field in BOUNDARY_FIELDS:
                    reference = self.run_lane(self.external(build, flag, **{field: []}), adjudications)
                    for value in (None, "", " "):
                        with self.subTest(external=flag, shape=shape, field=field, value=value):
                            result = self.run_lane(self.external(build, flag, **{field: value}), adjudications)
                            ext = lane(result, "ext")
                            self.assertEqual(ext["synthesis_use"], "quarantine")
                            self.assertEqual(ext["boundary_status"], "boundary-tainted")
                            self.assert_external_block(result)
                            self.assert_diagnosed(result, field)
                            self.assertEqual(result["blocked_reasons"], reference["blocked_reasons"])
                            self.assertEqual(ext["synthesis_use"], lane(reference, "ext")["synthesis_use"])

    def test_null_boundary_field_cannot_be_outvoted_by_a_clean_field(self) -> None:
        for field in BOUNDARY_FIELDS:
            for other in BOUNDARY_FIELDS:
                if other == field:
                    continue
                with self.subTest(field=field, other=other):
                    result = self.run_lane(self.external(**{field: None, other: "clear"}))
                    self.assertEqual(lane(result, "ext")["synthesis_use"], "quarantine")
                    self.assert_external_block(result)
                    self.assert_diagnosed(result, field)


class NullInputFieldSweepTests(ExternalLaneCase):
    """Sweep: other input fields where a present null was read as absent."""

    def test_valid_paths(self) -> None:
        for field, value in (("synthesis_use", "__drop__"), ("recommended_synthesis_use", "__drop__"),
                             ("provider_camp", "openai"), ("provider_family", "__drop__"), ("trust_domain", "__drop__")):
            with self.subTest(field=field, value=value):
                result = self.run_lane(self.external(**{field: value}))
                self.assertEqual(lane(result, "ext")["synthesis_use"], "primary")
                self.assertEqual(result["status"], "ready")
        claims = [{**entry, "zero_trust_claims": [self.claim]} for entry in self.internal()]
        result = run(claims, self.records, [], zero_trust_required=True)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["zero_trust_consensus"]["claim_warnings"], [])

    def test_null_use_field_is_malformed(self) -> None:
        # A null use field is an invalid use: never primary, diagnosed, and
        # counted as a possible quarantine for the external-input block.
        for field in ("synthesis_use", "recommended_synthesis_use"):
            for shape, build, adjudications in (
                ("disposition primary", accepted_unheld, []),
                ("recommended primary with a bound acceptance", recommended_primary, [acceptance("adj-a", "d-ext")]),
            ):
                if shape.startswith("recommended") and field == "recommended_synthesis_use":
                    continue
                with self.subTest(field=field, shape=shape):
                    result = self.run_lane(self.external(build, **{field: None}), adjudications)
                    self.assertEqual(lane(result, "ext")["synthesis_use"], "unknown")
                    self.assert_external_block(result)
                    self.assertIn("one or more inputs have an invalid synthesis_use or recommended_synthesis_use",
                                  result["blocked_reasons"])
                    self.assert_diagnosed(result, field)

    def test_null_or_blank_provider_label_is_malformed(self) -> None:
        for field in PROVIDER_LABEL_FIELDS:
            for value in (None, "", " "):
                with self.subTest(field=field, value=value):
                    result = self.run_lane(self.external(**{field: value}))
                    ext = lane(result, "ext")
                    self.assertEqual(ext["synthesis_use"], "salvage-only")
                    self.assertEqual(ext["primary_use_withheld"], "malformed provider label")
                    self.assertEqual(result["primary_input_count"], 2)
                    self.assert_diagnosed(result, field)

    def test_null_claims_are_diagnosed_and_not_counted(self) -> None:
        with self.subTest(field="zero_trust_claims"):
            inputs = [{**entry, "zero_trust_claims": None} for entry in self.internal()]
            result = run(inputs, self.records, [], zero_trust_required=True)
            self.assertEqual(result["zero_trust_consensus"]["claim_warnings"],
                             ["opus: zero_trust_claims is null or not a list",
                              "chatgpt: zero_trust_claims is null or not a list"])
            self.assertEqual(result["status"], "blocked")
        for field in ("claim_id", "category", "key", "value", "claim_type", "evidence"):
            with self.subTest(field=field):
                # A null value used to become the text "None", and a null
                # claim_id or claim_type the default, so two null claims agreed.
                claims = [{**entry, "zero_trust_claims": [{**self.claim, field: None}]} for entry in self.internal()]
                result = run(claims, self.records, [], zero_trust_required=True)
                consensus = result["zero_trust_consensus"]
                self.assertEqual(consensus["claim_count"], 0)
                self.assertEqual(consensus["comparable_claim_count"], 0)
                self.assertEqual(consensus["claim_warnings"],
                                 [f"opus: claim 1 has null {field}", f"chatgpt: claim 1 has null {field}"])
                self.assertIn("zero-trust consensus requires explicit zero_trust_claims on accepted primary inputs",
                              result["blocked_reasons"])
                self.assertEqual(result["status"], "blocked")


class UseLevelQuarantineTests(ExternalLaneCase):
    """A quarantine named by synthesis_use or recommended_synthesis_use reaches the external-input block."""

    use_fields = ("synthesis_use", "recommended_synthesis_use")

    def test_valid_paths(self) -> None:
        # Controls: a restrictive use that is not a quarantine, and a bound
        # rejection alone, leave the external-input block out (rejection stays
        # outside it, as an evaluator rejection does).
        for field in self.use_fields:
            for value in ("salvage-only", "partial-only", "open-risk", "reject"):
                with self.subTest(field=field, value=value):
                    result = self.run_lane(self.external(**{field: value}))
                    self.assertNotIn(EXTERNAL_BLOCK, result["blocked_reasons"])
                    self.assertFalse(lane(result, "ext")["quarantine_in_force"])
                    self.assertEqual(result["primary_input_count"], 2)
        result = self.run_lane(self.external(recommended_primary),
                               [adjudication("adj-r", "d-ext", decision="rejected", evidence=[])])
        self.assertEqual(lane(result, "ext")["synthesis_use"], "reject")
        self.assertNotIn(EXTERNAL_BLOCK, result["blocked_reasons"])
        self.assertEqual(result["status"], "partial")

    def test_use_level_quarantine_blocks(self) -> None:
        # Reviewer reproduction: the lane was in quarantined_inputs, but the
        # result was partial, blocked false.
        for flag in (True, "__absent__"):
            for field in self.use_fields:
                for value in ("quarantine", "quarantined"):
                    with self.subTest(external=flag, field=field, value=value):
                        result = self.run_lane(self.external(flag=flag, **{field: value}))
                        self.assertEqual(lane(result, "ext")["synthesis_use"], "quarantine")
                        self.assertIn(lane(result, "ext"), result["quarantined_inputs"])
                        self.assert_external_block(result)

    def test_malformed_external_flag_is_read_both_ways(self) -> None:
        for field in self.use_fields:
            for value in self.malformed_flags:
                with self.subTest(reading="read as external", field=field, external=value):
                    result = self.run_lane(self.external(flag=value, **{field: "quarantine"}))
                    self.assertEqual(lane(result, "ext")["synthesis_use"], "quarantine")
                    self.assert_external_block(result)
                    self.assertEqual([item["index"] for item in rejections(result, "inputs")], [2])
                with self.subTest(reading="read as internal", field=field, external=value):
                    result = self.run_lane(self.external(**{field: "quarantine"}), [],
                                           returned("other", None, external=value))
                    self.assertEqual(result["primary_input_count"], 3)
                    self.assertIn(EXTERNAL_BLOCK, result["blocked_reasons"])
                    self.assertEqual(result["status"], "blocked")

    def test_requested_quarantine_on_a_held_or_rejected_return_counts(self) -> None:
        # Sweep: a hold or a bound rejection decides the final use first, but
        # the requested quarantine is still in force.
        rejection = [adjudication("adj-r", "d-ext", decision="rejected", evidence=[])]
        for field in self.use_fields:
            for name, build, adjudications, use in (("tripwire held", tripwire_held, [], "open-risk"),
                                                    ("bound rejection", accepted_unheld, rejection, "reject")):
                with self.subTest(field=field, case=name):
                    result = self.run_lane(self.external(build, **{field: "quarantine"}), adjudications)
                    self.assertEqual(lane(result, "ext")["synthesis_use"], use)
                    self.assert_external_block(result)

    def test_malformed_use_field_counts_as_a_possible_quarantine(self) -> None:
        # Sweep: a malformed use field may be read as quarantine, so the block
        # applies, as it does for a malformed boundary field.
        for field in self.use_fields:
            for value in (None, "", "invalid", 7, True, [], ["quarantine"], {}):
                for shape, build, adjudications in (("disposition primary", accepted_unheld, []),
                                                    ("salvage recommendation", accepted_unheld, [])):
                    fields = {field: value}
                    if shape == "salvage recommendation":
                        if field == "recommended_synthesis_use":
                            continue
                        fields["recommended_synthesis_use"] = "salvage-only"
                    with self.subTest(field=field, value=value, shape=shape):
                        result = self.run_lane(self.external(build, **fields), adjudications)
                        self.assert_external_block(result)
                        self.assert_diagnosed(result, field)

    def test_an_external_input_outside_any_quarantine_lifts_the_block(self) -> None:
        for field in self.use_fields:
            with self.subTest(field=field, case="second clean external input"):
                result = self.run_lane(self.external(**{field: "quarantine"}), [],
                                       returned("other", None, external=True))
                self.assertNotIn(EXTERNAL_BLOCK, result["blocked_reasons"])
                self.assertEqual(result["status"], "partial")
            with self.subTest(field=field, case="quarantine on an internal input"):
                result = run([*self.internal(), returned("local", None, external=False, **{field: "quarantine"})],
                             self.records, [])
                self.assertNotIn(EXTERNAL_BLOCK, result["blocked_reasons"])
                self.assertEqual(result["status"], "partial")



# Round 6: a malformed or overridden input never clears a refusal. A malformed
# element is unresolved and blocks the decision it would have fed; a
# well-formed override does not clear a restriction.
INVALID_USE_BLOCK = "one or more inputs have an invalid synthesis_use or recommended_synthesis_use"
UNKNOWN_DISPOSITION_BLOCK = "one or more inputs have unknown evaluator dispositions"
DIVERGENCE_BLOCK = "zero-trust cross-domain divergence requires architect resolution"


def zt_claim(category: str, key: str, value: str, **fields: object) -> dict:
    entry = {"claim_id": f"{category}:{key}", "category": category, "key": key, "value": value,
             "claim_type": "security_assertion", "evidence": "cited the configured setting"}
    return apply_overrides(entry, fields)


AUTH = zt_claim("auth", "jwt", "RS256 only")
CIPHER = zt_claim("crypto", "cipher", "AES-256-GCM")
OTHER_CIPHER = zt_claim("crypto", "cipher", "AES-128-CBC")
CONSENSUS_RECORDS = [CONTROL, dispatch("d-chatgpt", "chatgpt_pro_browser_master_reviewer"),
                     dispatch("d-local", "openshift_ai_vllm_worker")]


def consensus(*claim_sets: list, extra: tuple = (), **kwargs: object) -> dict:
    """Two (or three) bound primaries from separate trust domains, each with its claims."""

    lanes = (("opus", "d-opus"), ("chatgpt", "d-chatgpt"), ("local", "d-local"))
    inputs = [returned(name, dispatch_id, external=False, zero_trust_claims=claims)
              for (name, dispatch_id), claims in zip(lanes, claim_sets)]
    kwargs.setdefault("zero_trust_required", True)
    return run([*inputs, *extra], CONSENSUS_RECORDS, [], **kwargs)


def unresolved_reasons(result: dict) -> list[str]:
    return [reason for reason in result["blocked_reasons"] if reason.startswith("zero-trust consensus is unresolved")]


# Each malformed version of the conflicting claim. Before round 6 every one was
# dropped from the comparison with a warning, which removed the disagreement.
MALFORMED_CLAIM_VARIANTS = {
    "subject: null claim_id": {"claim_id": None},
    "subject: null category": {"category": None},
    "subject: null key": {"key": None},
    "subject: blank category": {"category": " "},
    "subject: blank key": {"key": ""},
    "subject: missing key": {"key": "__drop__"},
    "subject: unknown category": {"category": "cryptography"},
    "subject: null claim_type": {"claim_type": None},
    "subject: unknown claim_type": {"claim_type": "opinion"},
    "value: null": {"value": None},
    "value: blank": {"value": " "},
    "value: missing": {"value": "__drop__"},
    "evidence: null": {"evidence": None},
}


class MalformedClaimConsensusTests(unittest.TestCase):
    """A malformed claim leaves required consensus unresolved instead of dropping out of it."""

    def test_valid_paths(self) -> None:
        # Controls: matching claims are ready; a real disagreement blocks with
        # divergence 40; no claim is unresolved in either case.
        result = consensus([AUTH, CIPHER], [AUTH, CIPHER])
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["zero_trust_consensus"].get("unresolved_claims", []), [])
        result = consensus([AUTH, CIPHER], [AUTH, OTHER_CIPHER])
        self.assertEqual(result["zero_trust_consensus"]["divergence_score"], 40)
        self.assertIn(DIVERGENCE_BLOCK, result["blocked_reasons"])
        self.assertEqual(result["zero_trust_consensus"].get("unresolved_claims", []), [])
        result = consensus([AUTH], [AUTH])
        self.assertEqual(result["status"], "ready")
        # Evidence is optional: a claim without it is still a well-formed claim.
        result = consensus([AUTH, CIPHER], [AUTH, zt_claim("crypto", "cipher", "AES-256-GCM", evidence="__drop__")])
        self.assertEqual(result["status"], "ready")

    def test_malformed_claim_agreement_family(self) -> None:
        rows = (
            ("test_malformed_conflicting_claim_beside_a_valid_matching_claim_blocks", OTHER_CIPHER, True),
            ("test_malformed_matching_claim_blocks", CIPHER, False),
        )
        for row_id, claim, detailed in rows:
            for name, fields in MALFORMED_CLAIM_VARIANTS.items():
                with self.subTest(row=row_id, variant=name):
                    malformed = apply_overrides(copy.deepcopy(claim), copy.deepcopy(fields))
                    result = consensus([AUTH, CIPHER], [AUTH, malformed])
                    self.assertEqual(result["status"], "blocked")
                    reasons = unresolved_reasons(result)
                    if detailed:
                        zero = result["zero_trust_consensus"]
                        self.assertTrue(result["blocked"])
                        self.assertEqual(zero["consensus_status"], "blocked")
                        self.assertEqual([(item["lane"], item["claim"]) for item in zero["unresolved_claims"]],
                                         [("chatgpt", 2)])
                        self.assertEqual(len(reasons), 1, result["blocked_reasons"])
                        self.assertIn("chatgpt claim 2", reasons[0])
                        self.assertTrue(zero["claim_warnings"])
                    else:
                        self.assertEqual(len(reasons), 1)


    def test_non_string_claim_fields_are_unresolved(self) -> None:
        # Before round 6 a non-string value became its text, so two lanes with
        # the same non-string value agreed.
        for field, value in (("value", 7), ("value", ["AES-256-GCM"]), ("value", True), ("key", 7),
                             ("category", ["crypto"]), ("claim_id", 7), ("claim_type", {}), ("evidence", 7),
                             ("evidence", {"cite": "x"})):
            with self.subTest(field=field, value=value):
                malformed = apply_overrides(CIPHER, {field: value})
                result = consensus([AUTH, malformed], [AUTH, malformed])
                self.assertEqual(result["status"], "blocked")
                self.assertEqual(len(unresolved_reasons(result)), 2, result["blocked_reasons"])

    def test_non_object_claim_or_claim_list_is_unresolved(self) -> None:
        for name, chatgpt_claims in (("claim is a string", [AUTH, "crypto:cipher AES-128-CBC"]),
                                     ("claim is null", [AUTH, None]),
                                     ("claim is an array", [AUTH, [OTHER_CIPHER]])):
            with self.subTest(case=name):
                result = consensus([AUTH, CIPHER], chatgpt_claims)
                self.assertEqual(result["status"], "blocked")
                self.assertIn("chatgpt claim 2", unresolved_reasons(result)[0])
        # A third provider whose claims field is malformed: the two others agree.
        for value in (None, "AES-128-CBC", {"claim_id": "crypto:cipher"}):
            with self.subTest(case="third provider claims field", value=value):
                result = consensus([AUTH, CIPHER], [AUTH, CIPHER], value)
                self.assertEqual(result["zero_trust_consensus"]["independent_trust_domain_count"], 3)
                self.assertEqual(result["status"], "blocked")
                self.assertIn("local", unresolved_reasons(result)[0])

    def test_negative_controls(self) -> None:
        # Consensus is opt-in: a malformed claim is reported but does not block
        # when consensus is not required.
        result = consensus([AUTH, CIPHER], [AUTH, apply_overrides(OTHER_CIPHER, {"evidence": None})],
                           zero_trust_required=False)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["zero_trust_consensus"]["claim_warnings"], ["chatgpt: claim 2 has null evidence"])
        # A malformed claim on an input that is not primary is never read.
        salvage = returned("local", "d-local", external=False, synthesis_use="salvage-only",
                           zero_trust_claims=[apply_overrides(OTHER_CIPHER, {"value": None})])
        result = consensus([AUTH, CIPHER], [AUTH, CIPHER], extra=(salvage,))
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["zero_trust_consensus"].get("unresolved_claims", []), [])


class ConsensusDiscardSweepTests(unittest.TestCase):
    """Sweep: other ways a claim dropped out of, or was underweighted in, the comparison."""

    def test_inconsistent_claims_under_one_claim_id_are_unresolved(self) -> None:
        # Before round 6 the first claim's category set the weight, so input
        # order decided whether a disagreement reached the escalation threshold.
        relabelled = zt_claim("data_handling", "cipher", "AES-128-CBC", claim_id="crypto:cipher")
        for order in ("crypto first", "data_handling first"):
            with self.subTest(order=order):
                sets = ([AUTH, CIPHER], [AUTH, relabelled])
                result = consensus(*(sets if order == "crypto first" else sets[::-1]))
                zero = result["zero_trust_consensus"]
                self.assertEqual(zero["divergence_score"], 40)
                self.assertEqual(result["status"], "blocked")
                self.assertEqual([item["claim_id"] for item in zero["unresolved_claims"]], ["crypto:cipher"])
        for name, fields in (("key differs", {"key": "mode"}), ("claim_type differs", {"claim_type": "factual"})):
            with self.subTest(case=name):
                result = consensus([AUTH, CIPHER], [AUTH, apply_overrides(CIPHER, fields)])
                self.assertEqual(result["status"], "blocked")
                self.assertEqual(len(unresolved_reasons(result)), 1)

    def test_primary_input_outside_the_domain_count_cannot_drop_its_claims(self) -> None:
        # A primary input whose labels conflict with its dispatch record, or a
        # legacy unbound primary, still feeds the synthesis; its conflicting
        # claims used to vanish from the comparison.
        conflicted = returned("local", "d-local", external=False, provider_family="openai",
                              zero_trust_claims=[AUTH, OTHER_CIPHER])
        legacy = returned("legacy", None, external=False, zero_trust_claims=[AUTH, OTHER_CIPHER])
        for name, extra in (("label conflict", conflicted), ("unbound legacy primary", legacy)):
            with self.subTest(case=name):
                result = consensus([AUTH, CIPHER], [AUTH, CIPHER], extra=(extra,))
                self.assertEqual(lane(result, extra["lane"])["synthesis_use"], "primary")
                self.assertEqual(result["zero_trust_consensus"]["independent_trust_domain_count"], 2)
                self.assertEqual(result["status"], "blocked")
                self.assertIn(extra["lane"], unresolved_reasons(result)[0])

    def test_controls(self) -> None:
        for name, extra in (
            ("legacy primary without claims", returned("legacy", None, external=False)),
            ("legacy primary with an empty claim list", returned("legacy", None, external=False, zero_trust_claims=[])),
        ):
            with self.subTest(case=name):
                result = consensus([AUTH, CIPHER], [AUTH, CIPHER], extra=(extra,))
                self.assertEqual(result["status"], "ready")
        result = consensus([AUTH, CIPHER], [AUTH, zt_claim("crypto", "cipher", "AES-256-GCM", claim_id="crypto:cipher")])
        self.assertEqual(result["status"], "ready")


EXPLICIT_USES = ("primary", "salvage-only", "partial-only", "open-risk", "quarantine", "reject", "salvage", "rejected")


class RecommendedQuarantineTests(ExternalLaneCase):
    """An explicit use may set the final use but does not clear a recommended quarantine."""

    def final_use(self, explicit: str, authorized: bool) -> str:
        if explicit == "primary":
            return "quarantine" if authorized else "unknown"
        return {"salvage": "salvage-only", "rejected": "reject"}.get(explicit, explicit)

    def cases(self):
        for explicit in EXPLICIT_USES:
            authorizations = (True, False) if explicit == "primary" else (False,)
            for authorized in authorizations:
                adjudications = [acceptance("adj-a", "d-ext")] if authorized else []
                yield explicit, authorized, adjudications

    def assert_recommended_quarantine(self, result: dict, explicit: str, authorized: bool) -> None:
        ext = lane(result, "ext")
        self.assert_external_block(result)
        self.assertEqual(ext["synthesis_use"], self.final_use(explicit, authorized))
        self.assertEqual(ext["recommended_synthesis_use"], "quarantine")
        self.assertIn("recommended_synthesis_use", ext["quarantine_sources"])
        self.assertIn("ext", result["quarantine_in_force_inputs"])

    def test_valid_paths(self) -> None:
        # Controls: a recommendation that is not quarantine adds no quarantine,
        # whatever the explicit use.
        for recommended in ("primary", "salvage-only"):
            for explicit, authorized, adjudications in self.cases():
                if explicit in {"quarantine"}:
                    continue
                with self.subTest(recommended=recommended, explicit=explicit, authorized=authorized):
                    result = self.run_lane(
                        self.external(synthesis_use=explicit, recommended_synthesis_use=recommended), adjudications)
                    self.assertFalse(lane(result, "ext")["quarantine_in_force"])
                    self.assertNotIn(EXTERNAL_BLOCK, result["blocked_reasons"])
        result = self.run_lane(self.external(synthesis_use="primary"), [acceptance("adj-a", "d-ext")])
        self.assertEqual(lane(result, "ext")["synthesis_use"], "primary")
        self.assertEqual(result["status"], "ready")

    def test_explicit_use_does_not_clear_a_recommended_quarantine(self) -> None:
        # Reviewer reproduction: an explicit salvage-only beside a quarantine
        # recommendation gave ready and quarantine_in_force false.
        for flag in (True, "__absent__", *self.malformed_flags):
            for explicit, authorized, adjudications in self.cases():
                with self.subTest(reading="read as external", external=flag, explicit=explicit,
                                  authorized=authorized):
                    entry = self.external(flag=flag, synthesis_use=explicit, recommended_synthesis_use="quarantine")
                    self.assert_recommended_quarantine(self.run_lane(entry, adjudications), explicit, authorized)

    def test_explicit_use_beside_an_ambiguous_neighbour(self) -> None:
        # The other reading: a clean neighbour with a malformed flag may be
        # internal, so the block applies.
        for value in self.malformed_flags:
            for explicit, authorized, adjudications in self.cases():
                with self.subTest(reading="neighbour read as internal", external=value, explicit=explicit,
                                  authorized=authorized):
                    entry = self.external(synthesis_use=explicit, recommended_synthesis_use="quarantine")
                    result = self.run_lane(entry, adjudications, returned("other", None, external=value))
                    ext = lane(result, "ext")
                    self.assertEqual(ext["synthesis_use"], self.final_use(explicit, authorized))
                    self.assertTrue(ext["quarantine_in_force"])
                    self.assertIn(EXTERNAL_BLOCK, result["blocked_reasons"])
                    self.assertEqual(result["status"], "blocked")

    def test_recommended_quarantine_on_an_internal_input_keeps_the_result_partial(self) -> None:
        # Without an external-input block the quarantine still stops "ready".
        for explicit, authorized, adjudications in self.cases():
            with self.subTest(explicit=explicit, authorized=authorized):
                entry = self.external(flag=False, synthesis_use=explicit, recommended_synthesis_use="quarantine")
                result = self.run_lane(entry, adjudications)
                self.assertTrue(lane(result, "ext")["quarantine_in_force"])
                self.assertEqual(result["primary_input_count"], 2)
                self.assertNotEqual(result["status"], "ready")

    def test_a_clean_external_input_lifts_only_the_external_block(self) -> None:
        result = self.run_lane(self.external(synthesis_use="salvage-only", recommended_synthesis_use="quarantine"),
                               [], returned("other", None, external=True))
        self.assertNotIn(EXTERNAL_BLOCK, result["blocked_reasons"])
        self.assertEqual(result["status"], "partial")
        self.assertTrue(lane(result, "ext")["quarantine_in_force"])


class OverrideSweepTests(ExternalLaneCase):
    """Sweep: other malformed or overriding values that removed a restriction."""

    def internal_lane(self, **fields: object) -> dict:
        return self.external(flag=False, **fields)

    def test_valid_paths(self) -> None:
        for fields in ({}, {"synthesis_use": "salvage-only"}, {"recommended_synthesis_use": "salvage-only"},
                       {"synthesis_use": "salvage-only", "recommended_synthesis_use": "salvage-only"},
                       {"synthesis_use": "salvage-only", "recommended_synthesis_use": "primary"}):
            with self.subTest(fields=fields):
                result = self.run_lane(self.internal_lane(**fields))
                self.assertEqual(result["status"], "ready")
                self.assertEqual(lane(result, "ext").get("overridden_restrictions", []), [])
        for disposition in ("accepted", "accepted-with-modification", "salvage-only"):
            with self.subTest(disposition=disposition):
                result = self.run_lane(self.internal_lane(disposition=disposition, synthesis_use="salvage-only"))
                self.assertEqual(result["status"], "ready")

    def test_malformed_use_field_beside_a_valid_one_blocks(self) -> None:
        # The valid field used to decide alone; the malformed one is unresolved.
        for field, other in (("synthesis_use", "recommended_synthesis_use"),
                             ("recommended_synthesis_use", "synthesis_use")):
            for value in (None, "", "invalid", 7, ["salvage-only"]):
                with self.subTest(field=field, value=value):
                    result = self.run_lane(self.internal_lane(**{field: value, other: "salvage-only"}))
                    self.assertEqual(lane(result, "ext")["synthesis_use"], "salvage-only")
                    self.assertIn(INVALID_USE_BLOCK, result["blocked_reasons"])
                    self.assertEqual(result["status"], "blocked")
                    self.assert_diagnosed(result, field)

    def test_use_field_does_not_resolve_an_unreadable_disposition(self) -> None:
        for value in (None, "", " ", "garbage", 7, []):
            for use in ("salvage-only", "partial-only", "open-risk", "reject", "quarantine"):
                for field in ("synthesis_use", "recommended_synthesis_use"):
                    with self.subTest(disposition=value, field=field, use=use):
                        result = self.run_lane(self.internal_lane(disposition=value, **{field: use}))
                        self.assertEqual(lane(result, "ext")["synthesis_use"], use)
                        self.assertIn(UNKNOWN_DISPOSITION_BLOCK, result["blocked_reasons"])
                        self.assertEqual(result["status"], "blocked")

    def test_salvage_only_use_does_not_clear_an_open_risk_or_partial_evaluation(self) -> None:
        for disposition in ("missing", "empty", "timed-out", "needs-investigation", "deferred"):
            for field in ("synthesis_use", "recommended_synthesis_use"):
                with self.subTest(disposition=disposition, field=field):
                    result = self.run_lane(self.internal_lane(disposition=disposition, **{field: "salvage-only"}))
                    ext = lane(result, "ext")
                    self.assertEqual(result["status"], "partial")
                    self.assertEqual(ext["synthesis_use"], "salvage-only")
                    self.assertEqual(ext["overridden_restrictions"], [f"evaluator disposition {disposition}"])

    def test_explicit_salvage_only_does_not_clear_a_more_restrictive_recommendation(self) -> None:
        for recommended in ("partial-only", "open-risk", "reject"):
            with self.subTest(recommended=recommended):
                result = self.run_lane(self.internal_lane(synthesis_use="salvage-only",
                                                          recommended_synthesis_use=recommended))
                ext = lane(result, "ext")
                self.assertEqual(result["status"], "partial")
                self.assertEqual(ext["synthesis_use"], "salvage-only")
                self.assertEqual(ext["overridden_restrictions"], [f"recommended_synthesis_use {recommended}"])

    def test_non_object_input_blocks(self) -> None:
        for value in ("not a record", 7, None, ["lane"]):
            with self.subTest(value=value):
                result = run([*self.internal(), value], self.records, [])
                self.assertEqual(result["input_summaries"][2]["synthesis_use"], "reject")
                # Round 8: the record may claim either internal dispatch, so neither binding holds (both used
                # to stay primary).
                self.assertEqual(result["primary_input_count"], 0)
                self.assertIn("one or more inputs are not objects, so what they would decide is unresolved",
                              result["blocked_reasons"])
                self.assertEqual(result["status"], "blocked")


# Round 7: a malformed restriction-bearing field, alone or beside any
# override, never leaves the result less restrictive than the most
# restrictive well-formed value of that field. The first three classes are
# the round-6 verdict's reproductions; FIELD_TABLE lists every field that can
# restrict, hold, block or quarantine, with its well-formed and malformed
# values and its disposition, and FieldTableTests checks it.
PEER = "peer-review-pending"
UNRESOLVED_REQUEST_BLOCK = ("one or more inputs request primary use that no applied adjudication authorizes, "
                            "and a hold or another restriction does not resolve the request")
UNREADABLE_RECORD_BLOCK = ("an adjudication record is not an object or has no readable dispatch_id, so what it "
                           "decides and the input it concerns are unresolved")
QUARANTINE_EXT = adjudication("adj-q", "d-ext", decision="quarantined", evidence=[])


class BlankHoldReasonTests(ExternalLaneCase):
    """Blank, non-string, space-padded and repeated hold reasons are malformed, never dropped."""

    malformed_lists = (
        [TRIPWIRE, ""], [TRIPWIRE, " "], [TRIPWIRE, "\t"], ["", TRIPWIRE], [TRIPWIRE, None], [TRIPWIRE, 7],
        [TRIPWIRE, []], [TRIPWIRE, {}], [TRIPWIRE, TRIPWIRE], [TRIPWIRE, TRIPWIRE.upper()], [TRIPWIRE + " "],
        [" " + TRIPWIRE], [""], [" "], [None],
    )

    def held(self, reasons: list, **fields: object) -> dict:
        return tripwire_held("ext", "d-ext", hold_reasons=reasons, **fields)

    def test_valid_paths(self) -> None:
        # A bound acceptance naming the tripwire clears [TRIPWIRE]; a peer-review
        # reason beside it is not clearable.
        cleared = self.run_lane(self.held([TRIPWIRE], external=True), [adjudication("adj-a", "d-ext")])
        self.assertEqual(lane(cleared, "ext")["synthesis_use"], "primary")
        self.assertEqual(cleared["status"], "ready")
        peer = self.run_lane(self.held([TRIPWIRE, PEER], external=True), [adjudication("adj-a", "d-ext")])
        self.assertEqual(lane(peer, "ext")["synthesis_use"], "open-risk")
        self.assertEqual(lane(peer, "ext")["adjudication"]["uncleared_hold_reasons"], [PEER])
        # The recommended primary use stays an unresolved request, which blocks.
        self.assertEqual(peer["blocked_reasons"], [UNRESOLVED_REQUEST_BLOCK])
        self.assertEqual(peer["status"], "blocked")

    def test_blank_reason_beside_a_clearable_one_is_not_cleared(self) -> None:
        # Reviewer reproduction: beside one control input, [TRIPWIRE, PEER]
        # blocked, and [TRIPWIRE, ""] or [TRIPWIRE, " "] was cleared to ready.
        records = [CONTROL, dispatch("d-ext", "codex_architecture_critic")]
        reference = run([self.held([TRIPWIRE, PEER]), control_input()], records, [adjudication("adj-a", "d-ext")])
        self.assertEqual(reference["status"], "blocked")
        for reasons in self.malformed_lists:
            with self.subTest(reasons=reasons):
                result = run([self.held(reasons), control_input()], records, [adjudication("adj-a", "d-ext")])
                ext = lane(result, "ext")
                self.assertEqual(ext["synthesis_use"], "open-risk")
                self.assertTrue(ext["hold_reasons_malformed"])
                self.assertFalse(ext["adjudication"]["authorizes_requested_use"])
                self.assertTrue(any(error.startswith("hold_reasons") for error in ext["input_errors"]))
                self.assertEqual(result["status"], "blocked")

    def test_blank_reason_beside_two_internal_primaries(self) -> None:
        for reasons in self.malformed_lists:
            with self.subTest(reasons=reasons):
                result = self.run_lane(self.held(reasons, external=True), [adjudication("adj-a", "d-ext")])
                self.assertEqual(lane(result, "ext")["synthesis_use"], "open-risk")
                self.assertEqual(result["blocked_reasons"], [UNRESOLVED_REQUEST_BLOCK])
                self.assertEqual(result["status"], "blocked")

    def test_blank_reason_without_the_flag_holds_the_input(self) -> None:
        # A blank reason used to drop out, leaving no reason and no hold.
        for reasons in ([""], [" "], ["", ""]):
            with self.subTest(reasons=reasons):
                entry = self.external(hold_reasons=reasons)
                result = self.run_lane(entry, [acceptance("adj-a", "d-ext")])
                ext = lane(result, "ext")
                self.assertTrue(ext["implementation_blocked"])
                self.assertEqual(ext["synthesis_use"], "open-risk")
                self.assertNotEqual(result["status"], "ready")


class UnreadableAdjudicationRecordTests(ExternalLaneCase):
    """An adjudication record that cannot be read stays unresolved unless provably unrelated or history."""

    def unreadable_records(self) -> dict:
        without_dispatch = {key: value for key, value in QUARANTINE_EXT.items() if key != "dispatch_id"}
        return {
            "null": None, "empty object": {}, "empty array": [], "string": "quarantined", "integer": 7,
            "array of the record": [QUARANTINE_EXT],
            "no dispatch_id": without_dispatch,
            "null dispatch_id and decision": {**QUARANTINE_EXT, "dispatch_id": None, "decision": None},
            "blank dispatch_id": {**QUARANTINE_EXT, "dispatch_id": " "},
        }

    def targeted_unreadable_records(self) -> dict:
        # Records that name ext's dispatch but cannot be read in full.
        return {
            "dispatch_id only": {"dispatch_id": "d-ext"},
            "dispatch_id and null decision": {"dispatch_id": "d-ext", "decision": None},
            "decision missing": {key: value for key, value in QUARANTINE_EXT.items() if key != "decision"},
            "unknown decision": {**QUARANTINE_EXT, "decision": "maybe"},
            "decision is an array": {**QUARANTINE_EXT, "decision": []},
        }

    def assert_ext_quarantined(self, result: dict) -> None:
        ext = lane(result, "ext")
        self.assertNotEqual(ext["synthesis_use"], "primary")
        self.assertTrue(ext["quarantine_in_force"])
        self.assertIn("quarantined", ext["pending_restrictions"])
        self.assertIn(EXTERNAL_BLOCK, result["blocked_reasons"])
        self.assertEqual(result["status"], "blocked")

    def test_valid_paths(self) -> None:
        self.assert_external_block(self.run_lane(self.external(), [QUARANTINE_EXT]))
        clean = self.run_lane(self.external(), [])
        self.assertEqual(lane(clean, "ext")["synthesis_use"], "primary")
        self.assertEqual(clean["status"], "ready")

    def test_unreadable_record_does_not_restore_primary_use(self) -> None:
        # Reviewer reproduction: replacing the quarantine with null or {}
        # restored external primary use and "ready".
        for name, record in self.unreadable_records().items():
            with self.subTest(record=name):
                result = self.run_lane(self.external(), [record])
                self.assert_ext_quarantined(result)
                self.assertEqual(lane(result, "ext")["adjudication"]["state"], "invalid")
                self.assertTrue(any("readable dispatch_id" in reason for reason in result["blocked_reasons"]))
                # A record with no readable binding at all may concern any
                # input, so no input stays primary. One whose digest names
                # ext's return is provably not about the other returns.
                readable_digest = isinstance(record, dict) and "return_sha256" in record
                self.assertEqual(result["primary_input_count"], 2 if readable_digest else 0)

    def test_targeted_unreadable_record_keeps_a_possible_quarantine(self) -> None:
        for name, record in self.targeted_unreadable_records().items():
            with self.subTest(record=name):
                result = self.run_lane(self.external(), [record])
                self.assert_external_block(result)
                self.assertEqual(lane(result, "ext")["adjudication"]["state"], "invalid")

    def test_mixed_valid_and_unreadable_records(self) -> None:
        for name, record in {**self.unreadable_records(), **self.targeted_unreadable_records()}.items():
            for valid in ([acceptance("adj-a", "d-ext")], [acceptance("adj-o", "d-opus")], [QUARANTINE_EXT]):
                with self.subTest(record=name, valid=valid[0]["adjudication_id"]):
                    result = self.run_lane(self.external(), [*copy.deepcopy(valid), record])
                    self.assert_ext_quarantined(result)

    def test_unrelated_or_historical_records_do_not_restrict(self) -> None:
        # Controls: a readable binding to another input or dispatch, or an
        # explicit readable history marker, makes the record unrelated.
        for name, records in {
            "other dispatch, unreadable decision": [{**QUARANTINE_EXT, "dispatch_id": "d-elsewhere", "decision": None}],
            "history (candidate), unreadable decision": [{**QUARANTINE_EXT, "candidate": OTHER_CANDIDATE,
                                                           "decision": None}],
            "history (scope), unreadable decision": [{**QUARANTINE_EXT, "scope": "bead:another-task",
                                                      "decision": []}],
            "history (digest)": [{**QUARANTINE_EXT, "return_sha256": sha("an earlier return"), "version": 2}],
        }.items():
            with self.subTest(records=name):
                result = self.run_lane(self.external(), records)
                self.assertEqual(lane(result, "ext")["synthesis_use"], "primary")
                self.assertFalse(lane(result, "ext")["quarantine_in_force"])
                self.assertEqual(result["status"], "ready")
        other_input = self.run_lane(self.external(), [{"dispatch_id": "d-opus", "decision": None}])
        self.assertEqual(lane(other_input, "ext")["synthesis_use"], "primary")
        self.assertFalse(lane(other_input, "ext")["quarantine_in_force"])
        self.assertTrue(lane(other_input, "opus")["quarantine_in_force"])

    def test_input_without_a_readable_dispatch_id_keeps_its_refusals(self) -> None:
        # Sweep (field table, input dispatch_id): an unreadable dispatch_id on
        # the input dropped the refusal recorded for its dispatch.
        for value in (None, "", " ", [], {}, 7, ["d-ext"], " d-ext", "__drop__"):
            with self.subTest(dispatch_id=value):
                result = self.run_lane(self.external(dispatch_id=value), [QUARANTINE_EXT])
                # Round 8: ext may name either internal dispatch, so the internal bindings do not hold either
                # (assert_external_block used to require both internal primaries).
                self.assertEqual(result["primary_input_count"], 0)
                self.assertNotEqual(lane(result, "ext")["synthesis_use"], "primary")
                self.assertTrue(lane(result, "ext")["quarantine_in_force"])
                self.assertIn(EXTERNAL_BLOCK, result["blocked_reasons"])
                self.assertEqual(result["status"], "blocked")
                for name in ("opus", "chatgpt"):
                    self.assertIn(WILDCARD_INPUT_REASON, lane(result, name)["dispatch_binding"]["reasons"])

    def test_failed_binding_beside_a_refusal_for_no_present_dispatch(self) -> None:
        # The input names another dispatch than the refused one, which no
        # input names; its binding failed, so the refusal may concern it.
        for value in ("d-unrecorded", "d-ext-typo"):
            with self.subTest(dispatch_id=value):
                result = self.run_lane(self.external(dispatch_id=value), [QUARANTINE_EXT])
                self.assertEqual(lane(result, "ext")["dispatch_binding"]["state"], "failed")
                self.assert_external_block(result)
        # A bound input is unrelated to a refusal for a dispatch no input names.
        bound = self.run_lane(self.external(), [{**QUARANTINE_EXT, "dispatch_id": "d-gone"}])
        self.assertEqual(lane(bound, "ext")["synthesis_use"], "primary")
        self.assertEqual(bound["status"], "ready")

    def test_legacy_input_beside_a_refusal_for_no_present_dispatch(self) -> None:
        # A refusal for a dispatch no input names cannot be shown to concern
        # another return than an input that names no dispatch.
        legacy = returned("ext", None, external=True)
        result = self.run_lane(legacy, [{**QUARANTINE_EXT, "dispatch_id": "d-gone"}])
        self.assertTrue(lane(result, "ext")["quarantine_in_force"])
        self.assertIn(EXTERNAL_BLOCK, result["blocked_reasons"])
        # An acceptance for such a dispatch restricts nothing.
        accepted = self.run_lane(legacy, [acceptance("adj-a", "d-gone")])
        self.assertEqual(lane(accepted, "ext")["synthesis_use"], "primary")
        self.assertEqual(accepted["status"], "ready")

    def test_unreadable_adjudication_list_holds_every_input(self) -> None:
        for value in ({}, "x", 7, {"adj-q": QUARANTINE_EXT}):
            with self.subTest(adjudications=value):
                result = run([*self.internal(), self.external()], self.records, value)
                self.assertEqual(result["primary_input_count"], 0)
                self.assertTrue(lane(result, "ext")["quarantine_in_force"])
                self.assertIn(EXTERNAL_BLOCK, result["blocked_reasons"])
                self.assertEqual(result["status"], "blocked")


class InvalidAdjudicationAnyUseTests(ExternalLaneCase):
    """An invalid or ambiguous adjudication restricts the input whatever its final use."""

    unreadable_decisions = (None, [], "", " ", 7, {}, "maybe", ["quarantined"], "__drop__")

    def quarantine_with(self, decision: object) -> dict:
        return apply_overrides(QUARANTINE_EXT, {"decision": decision})

    def test_valid_paths(self) -> None:
        ready = self.run_lane(self.external(synthesis_use="salvage-only"), [acceptance("adj-a", "d-ext")])
        self.assertEqual(lane(ready, "ext")["synthesis_use"], "salvage-only")
        self.assertEqual(ready["status"], "ready")
        self.assert_external_block(self.run_lane(self.external(synthesis_use="salvage-only"), [QUARANTINE_EXT]))

    def test_salvage_only_does_not_bypass_an_unreadable_decision(self) -> None:
        # Reviewer reproduction: salvage-only beside a quarantine whose
        # decision became null or [] gave ready with no blocked reasons.
        for decision in self.unreadable_decisions:
            with self.subTest(decision=decision):
                result = self.run_lane(self.external(synthesis_use="salvage-only"), [self.quarantine_with(decision)])
                ext = lane(result, "ext")
                self.assertEqual(ext["adjudication"]["state"], "invalid")
                self.assertEqual(ext["synthesis_use"], "quarantine")
                self.assertIn("pending adjudication record", ext["quarantine_sources"])
                self.assert_external_block(result)

    def test_every_explicit_use_keeps_an_unreadable_decision(self) -> None:
        for explicit in (*EXPLICIT_USES, "__drop__"):
            for decision in self.unreadable_decisions:
                for flag in (True, False):
                    with self.subTest(explicit=explicit, decision=decision, external=flag):
                        entry = self.external(flag=flag, synthesis_use=explicit)
                        result = self.run_lane(entry, [self.quarantine_with(decision)])
                        ext = lane(result, "ext")
                        self.assertNotEqual(ext["synthesis_use"], "primary")
                        self.assertTrue(ext["quarantine_in_force"])
                        self.assertNotEqual(result["status"], "ready")
                        if flag:
                            self.assertIn(EXTERNAL_BLOCK, result["blocked_reasons"])

    def test_invalid_or_ambiguous_acceptance_keeps_salvage_partial(self) -> None:
        for name, records in {
            "invalid acceptance": [acceptance("adj-a", "d-ext", version=2)],
            "ambiguous acceptances": [acceptance("adj-a", "d-ext"), acceptance("adj-b", "d-ext")],
        }.items():
            with self.subTest(case=name):
                result = self.run_lane(self.external(flag=False, synthesis_use="salvage-only"), records)
                ext = lane(result, "ext")
                self.assertEqual(ext["synthesis_use"], "salvage-only")
                self.assertTrue(ext["adjudication_unresolved"])
                self.assertEqual(ext["overridden_restrictions"],
                                 [f"adjudication resolution is {ext['adjudication']['state']}"])
                self.assertEqual(result["status"], "partial")


class TableSweepRegressionTests(ExternalLaneCase):
    """Fail-opens the field table found on 96daa6c beyond the three majors, mixed valid and malformed."""

    def internal_claims(self) -> list:
        return [{**entry, "zero_trust_claims": [AUTH, CIPHER]} for entry in self.internal()]

    def test_unreadable_scope_does_not_file_records_as_history(self) -> None:
        # An invalid acceptance held the input; with no readable scope every
        # record was filed as history, so the input became primary.
        for scope in (None, "", " ", [], 7):
            with self.subTest(scope=scope):
                invalid = run([*self.internal(), self.external()], self.records,
                              [acceptance("adj-a", "d-ext", version=2)], scope=scope)
                self.assertEqual(lane(invalid, "ext")["synthesis_use"], "open-risk")
                self.assertEqual(lane(invalid, "ext")["adjudication"]["state"], "invalid")
                self.assertNotEqual(invalid["status"], "ready")
                quarantined = run([*self.internal(), self.external()], self.records, [QUARANTINE_EXT], scope=scope)
                self.assertTrue(lane(quarantined, "ext")["quarantine_in_force"])
                self.assertIn(EXTERNAL_BLOCK, quarantined["blocked_reasons"])
        # Control: a readable other scope is history.
        history = run([*self.internal(), self.external()], self.records, [QUARANTINE_EXT], scope="bead:another-task")
        self.assertEqual(history["status"], "ready")

    def test_a_hold_does_not_resolve_an_unauthorized_primary_request(self) -> None:
        # An unauthorized primary request is "unknown" and blocks; a hold (well
        # formed or malformed), a quarantine or a taint used to turn it into a
        # partial result.
        for explicit in ("primary", "__drop__"):
            for fields in ({"implementation_blocked": True, "hold_reasons": [PEER]},
                           {"implementation_blocked": None}, {"hold_reasons": None}, {"hold_reasons": [TRIPWIRE, ""]},
                           {"boundary_status": None}, {"boundary_status": "boundary-tainted"},
                           {"disposition": "quarantined"}):
                with self.subTest(explicit=explicit, fields=fields):
                    entry = self.external(flag=False, synthesis_use=explicit, recommended_synthesis_use="primary",
                                          **fields)
                    result = self.run_lane(entry)
                    self.assertNotEqual(lane(result, "ext")["synthesis_use"], "primary")
                    self.assertIn(UNRESOLVED_REQUEST_BLOCK, result["blocked_reasons"])
                    self.assertEqual(result["status"], "blocked")
        # Controls: an authorized request, or a rejection that decides it, adds no such block.
        authorized = self.run_lane(self.external(recommended_synthesis_use="primary"), [acceptance("adj-a", "d-ext")])
        self.assertEqual(authorized["status"], "ready")
        rejected = self.run_lane(self.external(flag=False, recommended_synthesis_use="primary"),
                                 [adjudication("adj-r", "d-ext", decision="rejected", evidence=[])])
        self.assertNotIn(UNRESOLVED_REQUEST_BLOCK, rejected["blocked_reasons"])

    def test_unrecognized_boundary_status_taints(self) -> None:
        for field in BOUNDARY_FIELDS:
            for value in ("invalid", "unknown", "none", "pending"):
                for other in ("__drop__", "clear"):
                    with self.subTest(field=field, value=value, other=other):
                        fields = {field: value}
                        if other != "__drop__":
                            fields["boundary_taint_status" if field != "boundary_taint_status"
                                   else "boundary_status"] = other
                        result = self.run_lane(self.external(**fields))
                        ext = lane(result, "ext")
                        self.assertEqual(ext["boundary_status"], "boundary-tainted")
                        self.assert_external_block(result)
                        self.assert_diagnosed(result, field)
        for value in ("clear", "clean", "not-applicable", "not_tainted"):
            with self.subTest(control=value):
                self.assertEqual(self.run_lane(self.external(boundary_status=value))["status"], "ready")

    def test_missing_or_unreadable_disposition_is_a_possible_quarantine(self) -> None:
        for value in ("__drop__", None, "", " ", 7, [], "garbage"):
            for explicit in ("__drop__", "salvage-only", "primary"):
                with self.subTest(disposition=value, explicit=explicit):
                    entry = self.external(disposition=value, synthesis_use=explicit)
                    result = self.run_lane(entry, [acceptance("adj-a", "d-ext")])
                    ext = lane(result, "ext")
                    self.assertNotEqual(ext["synthesis_use"], "primary")
                    self.assertIn("unresolved evaluator disposition", ext["quarantine_sources"])
                    self.assertIn(UNKNOWN_DISPOSITION_BLOCK, result["blocked_reasons"])
                    self.assert_external_block(result)

    def test_salvage_only_does_not_clear_an_unreadable_disposition_or_use(self) -> None:
        for fields, restriction in (({"disposition": None}, "evaluator disposition is unresolved"),
                                    ({"disposition": "garbage"}, "evaluator disposition is unresolved"),
                                    ({"recommended_synthesis_use": None}, "a use field is malformed"),
                                    ({"recommended_synthesis_use": 7}, "a use field is malformed")):
            with self.subTest(fields=fields):
                result = self.run_lane(self.external(flag=False, synthesis_use="salvage-only", **fields))
                ext = lane(result, "ext")
                self.assertEqual(ext["synthesis_use"], "salvage-only")
                self.assertIn(restriction, ext["overridden_restrictions"])
                self.assertEqual(result["status"], "blocked")

    def test_unreadable_local_critic_marker_quarantines(self) -> None:
        for field in ("executor", "local_expected_response_contract", "local_response_contract"):
            for value in ("", " ", 7, [], {}, True, ["cwo-glm-critic-v2"]):
                with self.subTest(field=field, value=value):
                    result = self.run_lane(self.external(**{field: value}))
                    ext = lane(result, "ext")
                    self.assertEqual(ext["synthesis_use"], "quarantine")
                    self.assert_external_block(result)
                    self.assert_diagnosed(result, field)
            with self.subTest(field=field, value=None):
                # The evaluator writes null for a return that is not local critic evidence.
                self.assertEqual(self.run_lane(self.external(**{field: None}))["status"], "ready")

    def test_claims_on_an_input_out_of_primary_use_through_malformed_data_stay_unresolved(self) -> None:
        # Two internal primaries agree; ext dissents. A malformed field that
        # takes ext out of primary use used to drop its dissent.
        dissent = [AUTH, OTHER_CIPHER]
        baseline = run([*self.internal_claims(), self.external(zero_trust_claims=dissent)], self.records, [],
                       zero_trust_required=True)
        self.assertEqual(baseline["status"], "blocked")
        for fields, adjudications in (({"implementation_blocked": None}, []), ({"provider_family": None}, []),
                                      ({"boundary_status": None}, []), ({"return_sha256": None}, []),
                                      ({}, [acceptance("adj-a", "d-ext", version=2)]),
                                      ({"hold_reasons": [""]}, [])):
            with self.subTest(fields=fields, adjudications=len(adjudications)):
                entry = self.external(flag=False, zero_trust_claims=dissent, **fields)
                result = run([*self.internal_claims(), entry], self.records, adjudications, zero_trust_required=True)
                self.assertNotEqual(lane(result, "ext")["synthesis_use"], "primary")
                self.assertTrue(any(item["lane"] == "ext" for item in result["zero_trust_consensus"]["unresolved_claims"]))
                self.assertEqual(result["status"], "blocked")
        # Control: a well-formed salvage-only use is not read, by design.
        salvage = run([*self.internal_claims(), self.external(flag=False, synthesis_use="salvage-only",
                                                              zero_trust_claims=dissent)],
                      self.records, [], zero_trust_required=True)
        self.assertEqual(salvage["zero_trust_consensus"]["unresolved_claims"], [])

    def test_non_boolean_zero_trust_required_requires_consensus(self) -> None:
        dissent = [AUTH, OTHER_CIPHER]
        inputs = [*self.internal_claims(), self.external(flag=False, zero_trust_claims=dissent)]
        self.assertEqual(run(copy.deepcopy(inputs), self.records, [], zero_trust_required=False)["status"], "ready")
        for value in (None, 0, "", "false", [], {}):
            with self.subTest(zero_trust_required=value):
                result = run(copy.deepcopy(inputs), self.records, [], zero_trust_required=value)
                self.assertTrue(result["zero_trust_consensus"]["required"])
                self.assertEqual(result["status"], "blocked")


# Round 8. Each class starts with the round-7 verdict's reproduction. A lane is
# excluded from zero-trust consensus only by a resolved, readable reason: when
# its provenance, eligibility, binding or any deciding field is unresolved,
# its claims stay unresolved and block required consensus, on internal and
# external lanes alike. One decision parser serves validation and resolution.
DISSENT_RECORDS = [CONTROL, dispatch("d-chatgpt", "chatgpt_pro_browser_master_reviewer"),
                   dispatch("d-local", "openshift_ai_vllm_worker"), dispatch("d-glm", "rhoai_glm_compact_architecture_critic")]


def dissent_run(dissenter: dict, records: list | None = None, adjudications: list | None = None,
                peers_external: bool = False) -> dict:
    """Two agreeing primaries in two trust domains (anthropic, openai) beside a third lane."""

    peers = [returned("opus", "d-opus", external=peers_external, zero_trust_claims=[AUTH, CIPHER]),
             returned("chatgpt", "d-chatgpt", external=peers_external, zero_trust_claims=[AUTH, CIPHER])]
    return run([*peers, dissenter], records if records is not None else copy.deepcopy(DISSENT_RECORDS),
               adjudications or [], zero_trust_required=True)


def records_with(dispatch_id: str, **fields: object) -> list:
    records = copy.deepcopy(DISSENT_RECORDS)
    for record in records:
        if record["dispatch_id"] == dispatch_id:
            record.update(fields)
    return records


class UnresolvedProvenanceConsensusTests(unittest.TestCase):
    """Major 1: unknown or conflicting dispatch provenance cannot drop a lane's claims."""

    def dissenter(self, external: bool, claims: list | None = None) -> dict:
        return returned("local", "d-local", external=external, zero_trust_claims=claims or [AUTH, OTHER_CIPHER])

    def assert_unresolved(self, result: dict) -> None:
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(any(reason.startswith("zero-trust consensus is unresolved: local")
                            for reason in result["blocked_reasons"]), result["blocked_reasons"])
        self.assertNotEqual(lane(result, "local")["synthesis_use"], "primary")
        self.assertIn("dispatch provenance is unknown or conflicting", lane(result, "local")["unresolved_data"])

    def test_valid_paths(self) -> None:
        for external in (False, True):
            with self.subTest(external=external):
                dissent = dissent_run(self.dissenter(external))
                self.assertEqual(dissent["status"], "blocked")
                self.assertIn(DIVERGENCE_BLOCK, dissent["blocked_reasons"])
                self.assertEqual(dissent["zero_trust_consensus"]["independent_trust_domain_count"], 3)
                agree = dissent_run(self.dissenter(external, [AUTH, CIPHER]))
                self.assertEqual(agree["status"], "ready")
                agreeing_label = dissent_run(self.dissenter(external),
                                             records_with("d-local", provider_family="local-openai-compatible"))
                self.assertIn(DIVERGENCE_BLOCK, agreeing_label["blocked_reasons"])

    def test_unresolved_dispatch_provenance_family(self) -> None:
        conflicts = (("provider_family", "anthropic"), ("provider_family", "openai"),
                     ("provider_family", "google"), ("provider_family", "local"),
                     ("provider_family", "LOCAL-OPENAI-COMPATIBLE"), ("provider_key", "openai_manual"),
                     ("provider_key", "anthropic_manual"), ("underlying_provider_key", "internal_codex"))
        rows = (
            ("test_conflicting_provider_family_keeps_the_dissent", [AUTH, OTHER_CIPHER],
             [{field: value} for field, value in conflicts], True),
            ("test_unregistered_executor_keeps_the_dissent", [AUTH, OTHER_CIPHER],
             [{"executor": executor} for executor in UNREGISTERED_EXECUTORS], False),
            ("test_unresolved_provenance_keeps_even_agreeing_claims_unresolved", [AUTH, CIPHER],
             [{"provider_family": "anthropic"}], False),
        )
        for row_id, claims, overrides, check_binding in rows:
            for external in (False, True):
                for fields in overrides:
                    with self.subTest(row=row_id, external=external, fields=fields):
                        result = dissent_run(self.dissenter(external, copy.deepcopy(claims)),
                                             records_with("d-local", **copy.deepcopy(fields)))
                        self.assert_unresolved(result)
                        if check_binding:
                            self.assertTrue(lane(result, "local")["dispatch_binding"]["bound"])
                            self.assertFalse(lane(result, "local")["dispatch_binding"]["provenance_known"])



    def test_each_override_keeps_the_dissent(self) -> None:
        overrides = ({"synthesis_use": "salvage-only"}, {"synthesis_use": "primary"},
                     {"recommended_synthesis_use": "primary"}, {"synthesis_use": "partial-only"})
        for external in (False, True):
            for peers_external in (False, True):
                for fields in overrides:
                    with self.subTest(external=external, peers_external=peers_external, fields=fields):
                        entry = {**self.dissenter(external), **fields}
                        result = dissent_run(entry, records_with("d-local", provider_family="anthropic"),
                                             [acceptance("adj-local", "d-local")],
                                             peers_external=peers_external)
                        self.assert_unresolved(result)

    def test_a_readable_salvage_only_provider_is_excluded(self) -> None:
        # Control: a registered salvage-only provider is a resolved, readable reason to exclude the lane.
        records = copy.deepcopy(DISSENT_RECORDS) + [dispatch("d-gemini", "gemini_architecture_critic")]
        result = dissent_run(returned("gemini", "d-gemini", external=False, zero_trust_claims=[AUTH, OTHER_CIPHER]),
                             records)
        self.assertEqual(lane(result, "gemini")["synthesis_use"], "salvage-only")
        self.assertEqual(lane(result, "gemini")["unresolved_data"], [])
        self.assertEqual(result["status"], "ready")


class LocalV2EligibilityConsensusTests(unittest.TestCase):
    """Major 2: missing or malformed local critic v2 evidence keeps the lane's block, internal or external."""

    def glm(self, external: bool, claims: list | None = None, **fields: object) -> dict:
        entry = returned("glm", "d-glm", external=external, zero_trust_claims=claims or [AUTH, OTHER_CIPHER],
                         **LOCAL_V2_VALID)
        return apply_overrides(entry, fields)

    def test_valid_paths(self) -> None:
        for external in (False, True):
            with self.subTest(external=external):
                dissent = dissent_run(self.glm(external))
                self.assertEqual(lane(dissent, "glm")["synthesis_use"], "primary")
                self.assertIn(DIVERGENCE_BLOCK, dissent["blocked_reasons"])
                self.assertEqual(dissent_run(self.glm(external, [AUTH, CIPHER]))["status"], "ready")

    def test_malformed_v2_evidence_keeps_the_dissent(self) -> None:
        # Reviewer reproduction: failed v2 eligibility quarantined an internal dissenting lane with no
        # unresolved flag, turning blocked into partial.
        for external in (False, True):
            for field, valid in LOCAL_V2_VALID.items():
                if field in ("executor", "local_expected_response_contract", "local_response_contract"):
                    continue
                for value in (ABSENT,) + LOCAL_V2_MALFORMED[type(valid)]:
                    with self.subTest(external=external, field=field, value=value):
                        result = dissent_run(self.glm(external, **{field: "__drop__" if value == ABSENT else value}))
                        glm = lane(result, "glm")
                        self.assertEqual(glm["synthesis_use"], "quarantine")
                        self.assertTrue(glm["quarantine_in_force"])
                        self.assertTrue(any(field in error for error in glm["input_errors"]), glm["input_errors"])
                        self.assertEqual(result["status"], "blocked")
                        self.assertTrue(any(reason.startswith("zero-trust consensus is unresolved: glm")
                                            for reason in result["blocked_reasons"]), result["blocked_reasons"])

    def test_malformed_v2_evidence_keeps_even_agreeing_claims_unresolved(self) -> None:
        for external in (False, True):
            with self.subTest(external=external):
                result = dissent_run(self.glm(external, [AUTH, CIPHER], local_http_status="200"))
                self.assertEqual(result["status"], "blocked")
                self.assertTrue(any(reason.startswith("zero-trust consensus is unresolved: glm")
                                    for reason in result["blocked_reasons"]))

    def test_readable_failure_quarantines_and_excludes(self) -> None:
        # Control: a readable failing value is a resolved reason: the lane is quarantined and its claims
        # do not count. An internal lane leaves the result partial; an external one adds the external block.
        for field, value in (("local_completion_status", "incomplete"), ("local_v2_frame_valid", False),
                             ("local_http_status", 500)):
            with self.subTest(field=field):
                internal = dissent_run(self.glm(False, **{field: value}))
                self.assertEqual(lane(internal, "glm")["synthesis_use"], "quarantine")
                self.assertEqual(lane(internal, "glm")["unresolved_data"], [])
                self.assertEqual(internal["status"], "partial")
                external = dissent_run(self.glm(True, **{field: value}))
                self.assertIn(EXTERNAL_BLOCK, external["blocked_reasons"])


class DecisionSpellingTests(ExternalLaneCase):
    """Major 3: one decision parser serves validation and resolution; a variant spelling is never acceptance."""

    def test_valid_paths(self) -> None:
        salvage = self.run_lane(self.external(synthesis_use="salvage-only"), [acceptance("adj-ext", "d-ext")])
        self.assertEqual(lane(salvage, "ext")["synthesis_use"], "salvage-only")
        self.assertFalse(lane(salvage, "ext")["quarantine_in_force"])
        self.assertEqual(salvage["status"], "ready")
        promoted = self.run_lane(self.external(recommended_primary), [acceptance("adj-ext", "d-ext")])
        self.assertEqual(lane(promoted, "ext")["synthesis_use"], "primary")

    def test_invalid_accepting_spelling_keeps_possible_quarantine(self) -> None:
        # Reviewer reproduction: ACCEPTED or " accepted " beside an external salvage-only input gave partial
        # without a quarantine or the external-input block.
        for variant in DECISION_VARIANTS:
            for build, fields in ((accepted_unheld, {"synthesis_use": "salvage-only"}), (accepted_unheld, {}),
                                  (recommended_primary, {}), (tripwire_held, {})):
                with self.subTest(variant=variant, build=build.__name__, fields=fields):
                    record = acceptance("adj-ext", "d-ext", decision=variant)
                    if build is tripwire_held:
                        record = adjudication("adj-ext", "d-ext", decision=variant)
                    result = self.run_lane(self.external(build, **fields), [record])
                    ext = lane(result, "ext")
                    self.assertEqual(ext["adjudication"]["state"], "invalid")
                    self.assertEqual(ext["pending_restrictions"], ["quarantined", "rejected"])
                    self.assertTrue(ext["quarantine_in_force"])
                    self.assertIn(EXTERNAL_BLOCK, result["blocked_reasons"])
                    self.assertEqual(result["status"], "blocked")
                    rejected = rejections(result, "adjudications")
                    self.assertTrue(any(error.startswith("decision must be one of") for error in rejected[0]["errors"]))

    def test_variant_spelling_on_an_internal_or_legacy_lane(self) -> None:
        for variant in DECISION_VARIANTS:
            with self.subTest(variant=variant):
                internal = self.run_lane(self.external(flag=False, synthesis_use="salvage-only"),
                                         [acceptance("adj-ext", "d-ext", decision=variant)])
                self.assertTrue(lane(internal, "ext")["quarantine_in_force"])
                self.assertNotEqual(internal["status"], "ready")
                # Without a readable dispatch_id the record may concern any input and blocks.
                unattributed = self.run_lane(self.external(), [{**acceptance("adj-x", "d-ext", decision=variant),
                                                                "dispatch_id": None}])
                self.assertEqual(unattributed["status"], "blocked")

    def test_the_parser_is_shared(self) -> None:
        from cwo_core import adjudication as adjudication_module
        from cwo_core.synthesis_inputs import parse_decision
        for value in ("accepted", "accepted-with-changes", "rejected", "quarantined"):
            self.assertTrue(parse_decision({"decision": value}).valid)
        for value in DECISION_VARIANTS + (None, "", 7, ["accepted"], {"decision": "accepted"}):
            self.assertTrue(parse_decision({"decision": value}).unresolved, value)
        # No lenient second reading of a decision remains.
        for name in ("stated_decision", "restrictive_decision", "possible_restrictions"):
            self.assertFalse(hasattr(adjudication_module, name), name)


class DispatchIdWildcardTests(ExternalLaneCase):
    """An unreadable dispatch_id may name any dispatch, on an input or on a dispatch record."""

    def test_valid_paths(self) -> None:
        result = self.run_lane(self.external())
        self.assertEqual(result["status"], "ready")
        unrelated = run([*self.internal(), self.external()], [*self.records, dispatch("d-elsewhere", "x")], [])
        self.assertEqual(unrelated["primary_input_count"], 3)

    def test_unreadable_input_dispatch_id_holds_every_attempted_binding(self) -> None:
        for value in (None, "", " ", [], {}, 7, ["d-opus"], " d-opus", "__drop__"):
            with self.subTest(dispatch_id=value):
                result = self.run_lane(self.external(dispatch_id=value))
                self.assertEqual(result["primary_input_count"], 0)
                self.assertEqual(result["status"], "blocked")
                for name in ("opus", "chatgpt"):
                    self.assertIn(WILDCARD_INPUT_REASON, lane(result, name)["dispatch_binding"]["reasons"])

    def test_unreadable_record_dispatch_id_holds_every_attempted_binding(self) -> None:
        for value in (None, "", " ", [], {}, 7, ["d-opus"], " d-opus"):
            with self.subTest(dispatch_id=value):
                extra = {**dispatch("d-x", "codex_architecture_critic"), "dispatch_id": value}
                result = run([*self.internal(), self.external()], [*self.records, extra], [])
                self.assertEqual(result["primary_input_count"], 0)
                self.assertEqual(result["status"], "blocked")
                self.assertIn(WILDCARD_RECORD_REASON, lane(result, "opus")["dispatch_binding"]["reasons"])
        for value in NON_OBJECTS + ({},):
            with self.subTest(record=value):
                result = run([*self.internal(), self.external()], [*self.records, value], [])
                self.assertEqual(result["primary_input_count"], 0)

    def test_refusal_for_another_dispatch_may_concern_an_unreadable_input(self) -> None:
        # The refusal names opus's dispatch but ext's return digest: ext, whose dispatch_id cannot be read,
        # may be that dispatch's return.
        refusal = adjudication("adj-q", "d-opus", decision="quarantined", evidence=[], return_sha256=sha("return:d-ext"))
        result = self.run_lane(self.external(dispatch_id=None), [refusal])
        self.assertTrue(lane(result, "ext")["quarantine_in_force"])
        self.assertIn("quarantined", lane(result, "ext")["pending_restrictions"])
        # Control: a readable digest of another return is provable history for ext.
        history = adjudication("adj-q", "d-opus", decision="quarantined", evidence=[])
        control = self.run_lane(self.external(dispatch_id=None), [history])
        self.assertEqual(lane(control, "ext")["pending_restrictions"], [])

    def test_legacy_inputs_are_not_wildcards(self) -> None:
        result = run([*self.internal(), returned("legacy")], self.records, [])
        self.assertEqual(result["primary_input_count"], 3)
        self.assertEqual(result["status"], "ready")


class RawReadEliminationTests(unittest.TestCase):
    """synthesis.py and adjudication.py read no raw record; only cwo_core.synthesis_inputs does."""

    RAW_METHODS = {"get", "setdefault", "keys", "items", "values", "pop"}

    def downstream_functions(self) -> dict:
        import ast
        found = {}
        for name in ("synthesis.py", "adjudication.py"):
            tree = ast.parse((ROOT / "scripts" / "cwo_core" / name).read_text(encoding="utf-8"))
            functions = {}
            methods = {}
            for node in tree.body:
                if isinstance(node, ast.FunctionDef):
                    functions[node.name] = node
                elif isinstance(node, ast.ClassDef):
                    for item in node.body:
                        if isinstance(item, ast.FunctionDef):
                            methods.setdefault(item.name, []).append(item)
            if name == "adjudication.py":
                roots = set(functions) | set(methods)
            else:
                roots = {"evaluate_synthesis_inputs", "evaluate_zero_trust_consensus"}
            seen = set()
            pending = list(roots)
            while pending:
                current = pending.pop()
                if current in seen:
                    continue
                seen.add(current)
                for node in [functions[current]] if current in functions else methods.get(current, []):
                    for child in ast.walk(node):
                        if isinstance(child, ast.Call):
                            called = child.func.id if isinstance(child.func, ast.Name) else (
                                child.func.attr if isinstance(child.func, ast.Attribute) else None)
                            if called in functions or called in methods:
                                pending.append(called)
                        if isinstance(child, ast.Name) and child.id in functions:
                            pending.append(child.id)
            for current in seen:
                for node in [functions[current]] if current in functions else methods.get(current, []):
                    found[f"{name}:{node.name}:{node.lineno}"] = node
        return found

    def test_no_raw_read_in_synthesis_or_adjudication(self) -> None:
        import ast
        functions = self.downstream_functions()
        self.assertIn("synthesis.py:_decide_lane", {key.rsplit(":", 1)[0] for key in functions})
        self.assertIn("synthesis.py:_zero_trust_consensus", {key.rsplit(":", 1)[0] for key in functions})
        violations = []
        for key, node in functions.items():
            for child in ast.walk(node):
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) \
                        and child.func.attr in self.RAW_METHODS:
                    violations.append(f"{key}: .{child.func.attr}() at line {child.lineno}")
                if isinstance(child, ast.Subscript) and isinstance(child.ctx, ast.Load) \
                        and isinstance(child.slice, ast.Constant) and isinstance(child.slice.value, str):
                    violations.append(f"{key}: [{child.slice.value!r}] at line {child.lineno}")
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id == "isinstance" \
                        and len(child.args) == 2 and "dict" in ast.dump(child.args[1]):
                    violations.append(f"{key}: isinstance(..., dict) at line {child.lineno}")
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id == "dict" \
                        and child.args:
                    violations.append(f"{key}: dict(...) at line {child.lineno}")
        self.assertEqual(violations, [])

    def test_no_raw_access_at_run_time(self) -> None:
        # Every dict and list handed to evaluate_synthesis_inputs is wrapped so that any access made from
        # synthesis.py or adjudication.py is recorded; the parsed forms are the only way in.
        import sys as _sys
        violations: list = []
        downstream = (str(ROOT / "scripts" / "cwo_core" / "synthesis.py"),
                      str(ROOT / "scripts" / "cwo_core" / "adjudication.py"))

        def note(kind: str) -> None:
            caller = _sys._getframe(2)
            if caller.f_code.co_filename in downstream:
                violations.append((caller.f_code.co_filename.rsplit("/", 1)[-1], caller.f_code.co_name,
                                   caller.f_lineno, kind))

        def traced(name: str, base: type):
            def method(self, *args, **kwargs):
                note(name)
                return getattr(base, name)(self, *args, **kwargs)
            return method

        dict_methods = ("__getitem__", "get", "__contains__", "keys", "items", "values", "__iter__", "__len__",
                        "copy", "setdefault", "pop")
        list_methods = ("__getitem__", "__iter__", "__len__", "__contains__", "index", "count", "copy")
        TracingDict = type("TracingDict", (dict,), {name: traced(name, dict) for name in dict_methods})
        TracingList = type("TracingList", (list,), {name: traced(name, list) for name in list_methods})

        def wrap(value):
            if isinstance(value, dict):
                return TracingDict({key: wrap(item) for key, item in value.items()})
            if isinstance(value, list):
                return TracingList([wrap(item) for item in value])
            return value

        scenarios = []
        for baseline in (("accepted", None, "quarantining", True, "off"), ("recommended", "primary", "accepting",
                                                                            True, "dissent"),
                         ("local-v2", None, "none", False, "dissent"), ("tripwire-held", None, "accepting", True,
                                                                         "matching", True)):
            scenario = table_scenario(*baseline)
            scenarios.append(scenario)
            for row in FIELD_TABLE:
                for value in row["malformed"][:3]:
                    mutated = table_mutation(scenario, row, value)
                    if mutated is not None:
                        scenarios.append(mutated)
        for scenario in scenarios:
            plain = run_table(scenario)
            wrapped = evaluate_synthesis_inputs(wrap(scenario["inputs"]), dispatch_records=wrap(scenario["records"]),
                                                adjudications=wrap(scenario["adjudications"]),
                                                **{key: wrap(value) for key, value in scenario["arguments"].items()})
            self.assertEqual(wrapped["status"], plain["status"])
        self.assertGreater(len(scenarios), 200)
        self.assertEqual(sorted(set(violations)), [])


# Field table. Values: ABSENT removes the field; OWN_DISPATCH and OWN_DIGEST
# stand for the mutated lane's own dispatch_id and digest. "where" names the
# object that holds the field: an input, the external lane's adjudication
# record (and its first evidence item or its authority), its dispatch record,
# its second claim, a call argument, or a whole record or list.
ABSENT = "__drop__"
GLM_COMPACT = "rhoai_glm_compact_architecture_critic"
GLM_V1, GLM_V2 = "cwo-glm-critic-v1", "cwo-glm-critic-v2"
LOCAL_V2_VALID = {
    "executor": GLM_COMPACT, "local_expected_response_contract": GLM_V2, "local_response_contract": GLM_V2,
    "local_response_contract_status": "valid", "local_completion_status": "completed",
    "local_usable_final_content": True, "local_normalized_return_matches": True, "local_v2_frame_valid": True,
    "local_v2_identity_consistent": True, "local_response_model_status": "matched",
    "local_model_preflight_status": "passed", "local_http_status": 200,
}


# Readable values of each local critic v2 evidence kind (the eligible one and a readable failure), and values
# that are missing or of another kind (unresolved eligibility).
LOCAL_V2_WELL_FORMED = {str: lambda valid: (valid, "invalid"), bool: lambda valid: (True, False),
                        int: lambda valid: (200, 500)}
LOCAL_V2_MALFORMED = {str: (None, "", " ", {}, [], 7, True, ["x"], " valid"),
                      bool: (None, "", "true", 1, 0, {}, [], ["x"]),
                      int: (None, "", "200", 200.0, True, {}, [], ["x"])}
# Decision spellings that are not the exact decision strings (round 8: never read as acceptance).
DECISION_VARIANTS = ("ACCEPTED", " accepted ", "Accepted", "accepted ", " accepted", "accepted\n",
                     "ACCEPTED-WITH-CHANGES", " accepted-with-changes", "Accepted-With-Changes",
                     "accepted_with_changes", "REJECTED", " rejected", "Quarantined", " quarantined ")
UNREGISTERED_EXECUTORS = ("unregistered_architecture_critic", "CODEX_ARCHITECTURE_CRITIC",
                          "codex-architecture-critic", "rhoai_glm_unknown")


def OWN_DISPATCH(entry: dict) -> object:
    return entry.get("dispatch_id")


def OWN_DIGEST(entry: dict) -> object:
    return entry.get("return_sha256")


class _Agrees:
    """The registry-derived value of a dispatch identity label (a well-formed label that agrees)."""

    def __repr__(self) -> str:
        return "<agrees>"


AGREES = _Agrees()
DERIVED_IDENTITY = {
    "codex_architecture_critic": {"provider_key": "internal_codex", "provider_family": "openai",
                                  "underlying_provider_key": "internal_codex"},
    GLM_COMPACT: {"provider_key": "openshift_ai_vllm", "provider_family": "local-openai-compatible",
                  "underlying_provider_key": "openshift_ai_vllm"},
}
NULLISH = (None, "", " ")
WRONG_KIND = ({}, [], 7, 2.5, True, ["x"], {"k": "v"})
TEXT_MALFORMED = NULLISH + WRONG_KIND
NON_OBJECTS = (None, "", "not a record", 7, [], ["x"], True)


def field_row(where: str, field: str, required: bool | None, well_formed: tuple, malformed: tuple,
              restricts: str, disposition: str) -> dict:
    """One table row. ``required`` puts an absent field among the malformed values (True) or the
    well-formed ones (False); None is for a whole record, which has no absent form."""

    return {"where": where, "field": field, "required": required,
            "well_formed": ((ABSENT,) if required is False and ABSENT not in well_formed else ()) + tuple(well_formed),
            "malformed": ((ABSENT,) if required else ()) + tuple(malformed),
            "restricts": restricts, "disposition": disposition}


USES = ("primary", "salvage-only", "partial-only", "open-risk", "quarantine", "reject")
DISPOSITIONS = ("accepted", "accepted-with-modification", "salvage-only", "missing", "empty", "timed-out",
                "needs-investigation", "deferred", "rejected", "quarantined", "boundary-tainted")
DECIDES_NOTHING = "decides nothing; reported only"
# Public summaries are a distinct input surface, generated by the evaluator
# before these mutations. Tests in test_consensus_summary_boundary exercise
# this table rather than pretending the original input mutator visits it.
SUMMARY_FIELD_TABLE = (
    *(field_row("summary-label", field, False, (None, "openai", "anthropic"),
                ("", " ", [], {}, 7, True), "domain eligibility", "malformed labels remain unresolved")
      for field in ("provider_camp", "provider_family", "trust_domain")),
    field_row("summary", "adjudication_unresolved", False, (False,), (None, True, 0, 1, [], {}, "false"),
              "consensus uncertainty", "cannot clear a known or malformed unresolved flag"),
    *(field_row("summary", field, True, good, bad, "required consensus", "unresolved; never drop dissent")
      for field, good, bad in (
          ("lane", ("ext",), TEXT_MALFORMED + ("other",)),
          ("synthesis_use", USES, TEXT_MALFORMED + ("unknown",)),
          ("dispatch_binding", ({"state": "bound", "attempted": True, "bound": True,
                                 "dispatch_id": "d-ext", "return_sha256": sha("return:d-ext"),
                                 "provider_key": "internal_codex", "underlying_provider_key": "internal_codex",
                                 "provider_family": "openai", "provenance_known": True},), TEXT_MALFORMED),
          ("unresolved_data", ([], ["unresolved"]), NULLISH + ({}, 7, True, [None], [""])),
      )),
    *(field_row("summary-binding", field, True, good, bad, "binding and consensus", "unresolved")
      for field, good, bad in (
          ("state", ("absent", "failed", "bound"), TEXT_MALFORMED + ("unknown",)),
          ("attempted", (True, False), (None, 0, 1, "true", [], {})),
          ("bound", (True, False), (None, 0, 1, "true", [], {})),
          ("provenance_known", (True, False), (None, 0, 1, "true", [], {})),
          ("provider_family", ("openai", "anthropic"), TEXT_MALFORMED + ("invented-domain",)),
          ("provider_key", ("internal_codex",), TEXT_MALFORMED + ("unregistered",)),
          ("underlying_provider_key", ("internal_codex",), TEXT_MALFORMED + ("unregistered",)),
          ("dispatch_id", ("d-ext",), TEXT_MALFORMED + ("other",)),
          ("return_sha256", (sha("return:d-ext"),), TEXT_MALFORMED + ("f" * 64,)),
      )),
)


FIELD_TABLE = (
    # Inputs (each run on the external lane and on an internal primary).
    field_row("input", "disposition", True, DISPOSITIONS, TEXT_MALFORMED + (["accepted"], "unknown-disposition"),
              "use, unknown-disposition block, quarantine",
              "missing, null, blank, wrong kind or unknown: unresolved, blocks, possible quarantine (r7 adds missing "
              "and the quarantine)"),
    *(field_row("input", field, False, USES, TEXT_MALFORMED + (["primary"], "unknown-use"),
                "use, invalid-use block, quarantine",
                "null, blank, wrong kind or unknown: invalid-use block and possible quarantine whatever the other "
                "field says (r5, r6)")
      for field in ("synthesis_use", "recommended_synthesis_use")),
    field_row("input", "implementation_blocked", False, (True, False, 0, 1, "true", "false"),
              (None, "", " ", {}, [], 2, 2.5, "pending", [True]), "hold",
              "held, not clearable (r3, r5)"),
    field_row("input", "hold_reasons", False,
              ([], [TRIPWIRE], [PEER], [TRIPWIRE, PEER], [PACKET_ONLY_GO], ["unknown-hold"]),
              (None, "", " ", {}, 7, TRIPWIRE, [""], [" "], [None], [7], [[]], [TRIPWIRE, ""], [TRIPWIRE, " "],
               [TRIPWIRE, None], [TRIPWIRE, 7], [TRIPWIRE, TRIPWIRE], [TRIPWIRE, TRIPWIRE.upper()], [TRIPWIRE + " "],
               [" " + TRIPWIRE]),
              "hold, hold clearance",
              "held, not clearable; r7 makes blank, space-padded and repeated elements malformed instead of dropped"),
    *(field_row("input", field, False, ("clear", "not-applicable", "boundary-tainted", "clean", "tainted"),
                TEXT_MALFORMED + (["boundary-tainted"], "unknown-status"), "boundary taint (quarantine)",
                "tainted (r5); r7 also taints an unrecognized status string")
      for field in ("boundary_taint_status", "boundary_status", "share_boundary_status")),
    field_row("input", "external", False, (True, False), (None, "", " ", {}, [], 0, 1, "true", "false"),
              "external-input block", "read both ways (r4)"),
    *(field_row("input", field, False, ("openai", "anthropic", "google", "local"), TEXT_MALFORMED + (["openai"],),
                "salvage-only provider rule, trust domain",
                "never primary (r5); r7 keeps its claims unresolved under required consensus")
      for field in ("provider_camp", "provider_family", "trust_domain")),
    field_row("input", "dispatch_id", True, (OWN_DISPATCH, "d-unrecorded"),
              TEXT_MALFORMED + ([OWN_DISPATCH],) + (" d-ext",), "dispatch binding, adjudication target",
              "failed binding, never primary (r2); r7 keeps refusals that may concern it (records naming no "
              "present dispatch)"),
    field_row("input", "return_sha256", True, (OWN_DIGEST, sha("another return")),
              TEXT_MALFORMED + ("A" * 64, "a" * 10), "dispatch binding",
              "failed binding; refusals for its dispatch stay pending (r2, r3)"),
    field_row("input", "zero_trust_claims", False, ([], [AUTH], [AUTH, CIPHER]),
              (None, "", {}, 7, True, ["x"], [None], [7]), "zero-trust consensus",
              "unresolved, blocks required consensus (r6)"),
    field_row("input", "executor", False, (None, "codex_architecture_critic", GLM_COMPACT),
              ("", " ", {}, [], 7, True, [GLM_COMPACT]), "local critic v2 evidence (quarantine)",
              "null is the evaluator's not-applicable value; r7 quarantines any other value that is not a "
              "non-blank string"),
    *(field_row("input", field, False, (None, GLM_V1, GLM_V2), ("", " ", {}, [], 7, True, [GLM_V2]),
                "local critic v2 evidence (quarantine)",
                "null is the evaluator's not-applicable value; r7 quarantines any other value that is not a "
                "non-blank string")
      for field in ("local_expected_response_contract", "local_response_contract")),
    *(field_row("input", field, True, LOCAL_V2_WELL_FORMED[type(valid)](valid), LOCAL_V2_MALFORMED[type(valid)],
                "local critic v2 eligibility (quarantine, consensus)",
                "on v2 evidence a readable value other than the eligible one quarantines; r8: missing or of another "
                "kind is unresolved eligibility, quarantines and keeps the lane's claims unresolved (internal and "
                "external lanes); otherwise not read")
      for field, valid in LOCAL_V2_VALID.items()
      if field not in ("executor", "local_expected_response_contract", "local_response_contract")),
    *(field_row("input", field, False, ("x",), TEXT_MALFORMED, "nothing", DECIDES_NOTHING)
      for field in ("lane", "id", "name", "hold_classification", "reason", "evidence_quality_score")),
    *(field_row("input", field, False, (False,), TEXT_MALFORMED + ("architect",), "nothing",
                "role label; reported under ignored_authority_claims, grants nothing (r1)")
      for field in ("architect_adjudicated", "architect_upgrade", "architect_adjudication_authorized",
                    "implementation_block_override_authorized", "synthesis_use_authority")),
    field_row("input", "dispatch_binding", False, (),
              TEXT_MALFORMED + ({"bound": True, "provenance_known": True, "provider_family": "local"},),
              "nothing", "ignored: the computed binding replaces it"),
    field_row("input-record", "<input>", None, (), NON_OBJECTS, "everything the input decides",
              "rejected, blocks, counts as a quarantine (r6)"),
    # The external lane's adjudication record.
    *(field_row("adjudication", field, True, (), TEXT_MALFORMED + ("unknown",),
                "adjudication validity", "invalid record: holds the input, keeps a refusal it may state (r2, r3)")
      for field in ("record_type", "adjudication_id", "rationale", "adjudicator")),
    field_row("adjudication", "version", True, (1,), (None, "", "1", 1.0, 2, True, [], {}),
              "adjudication validity", "invalid record (r2)"),
    field_row("adjudication", "dispatch_id", True, ("d-ext", "d-elsewhere", "d-opus"),
              TEXT_MALFORMED + (["d-ext"], " d-ext"), "which input the record concerns",
              "r7: unattributed, unresolved for every input, blocks the result, possible quarantine"),
    field_row("adjudication", "return_sha256", True, (sha("return:d-ext"), sha("an earlier return")),
              TEXT_MALFORMED + (sha("return:d-ext").upper(),), "current or history",
              "invalid, not history (r3)"),
    field_row("adjudication", "candidate", True, (CANDIDATE, OTHER_CANDIDATE), TEXT_MALFORMED,
              "current or history", "invalid, not history (r3)"),
    field_row("adjudication", "scope", True, (SCOPE, "bead:another-task"), TEXT_MALFORMED,
              "current or history", "invalid, not history (r3)"),
    field_row("adjudication", "finding_ids", True, ([TRIPWIRE], ["finding:x"], [TRIPWIRE, PEER]),
              (None, "", {}, [], 7, TRIPWIRE, [""], [None], [7], [TRIPWIRE, TRIPWIRE]),
              "hold clearance", "invalid record (r2)"),
    field_row("adjudication", "decision", True, ("accepted", "accepted-with-changes", "rejected", "quarantined"),
              TEXT_MALFORMED + (["quarantined"], "approved") + DECISION_VARIANTS, "acceptance, rejection, quarantine",
              "r7: unreadable decision may be either refusal; invalid resolution restricts whatever the use; r8: one "
              "parser for validation and resolution, so a case or whitespace variant is never an acceptance"),
    field_row("adjudication", "supporting_evidence", False, ([],),
              (None, "", {}, 7, True, [None], [7], ["x"]), "acceptance validity", "invalid record (r2)"),
    field_row("adjudication", "authority", True, ({"rule": RULE},),
              TEXT_MALFORMED + ({"rule": None}, {"rule": ""}, {"rule": "architect-override"}, {"rule": [RULE]}),
              "acceptance validity", "invalid record (r2)"),
    *(field_row("evidence", field, True, well, malformed, "acceptance validity", "invalid record (r2)")
      for field, well, malformed in (
          ("artifact", ("validation/other.txt",), TEXT_MALFORMED),
          ("artifact_type", ("validation-log", "evaluator-result"), TEXT_MALFORMED + ("screenshot",)),
          ("sha256", (sha("other evidence"),), TEXT_MALFORMED + (sha("x").upper(),)),
          ("finding_ids", ([TRIPWIRE],), (None, "", {}, [], 7, [""], [None], [TRIPWIRE, TRIPWIRE])),
      )),
    field_row("adjudication-record", "<adjudication>", None, (), NON_OBJECTS + ({},),
              "the refusal or acceptance it holds",
              "r7: unattributed, unresolved for every input, blocks the result, possible quarantine"),
    field_row("extra-adjudication", "<adjudications[]>", False,
              (adjudication("adj-x", "d-elsewhere"),),
              NON_OBJECTS + ({}, {"dispatch_id": "d-ext"}, {"decision": "accepted"}),
              "a further record", "r7: unattributed or targeted unreadable record stays unresolved"),
    # The external lane's dispatch record.
    *(field_row("dispatch", field, True, well, malformed, "dispatch binding and provenance",
                "failed binding, never primary; refusals stay pending (r2)")
      for field, well, malformed in (
          ("record_type", (), TEXT_MALFORMED + ("dispatch",)),
          ("version", (), (None, "", "1", 1.0, 2, True, [], {})),
          ("dispatch_id", ("d-ext", "d-unrecorded"), TEXT_MALFORMED + (["d-ext"],)),
          ("executor", ("codex_architecture_critic", "claude_architecture_critic", "gemini_architecture_critic"),
           TEXT_MALFORMED + ([GLM_COMPACT],) + UNREGISTERED_EXECUTORS),
          ("return_sha256", (sha("return:d-ext"), sha("another return")), TEXT_MALFORMED),
          ("candidate", (CANDIDATE, OTHER_CANDIDATE), TEXT_MALFORMED),
      )),
    *(field_row("dispatch", field, False, (AGREES,), TEXT_MALFORMED + conflicting,
                "provenance, trust domain, consensus",
                "malformed: failed binding (r2); r8: a readable label that conflicts with the registry (or an "
                "unregistered executor) is unresolved provenance: never primary, and the lane's claims stay "
                "unresolved under required consensus")
      for field, conflicting in (
          ("provider_key", ("anthropic_manual", "google_gemini_manual", "openai_manual", "INTERNAL_CODEX")),
          ("provider_family", ("anthropic", "google", "local", "OpenAI", "x-unknown-family")),
          ("underlying_provider_key", ("anthropic_manual", "openai_manual", "internal_codex ")),
      )),
    field_row("dispatch-record", "<dispatch>", None, (), NON_OBJECTS + ({},), "the binding",
              "failed binding (r2)"),
    # The external lane's second claim (under required consensus).
    field_row("claim", "claim_id", False, ("crypto:cipher", "renamed"), TEXT_MALFORMED,
              "zero-trust consensus", "unresolved claim, blocks required consensus (r6)"),
    field_row("claim", "category", True, ("crypto", "data_handling"), TEXT_MALFORMED + ("unknown-category",),
              "zero-trust consensus", "unresolved claim (r6)"),
    field_row("claim", "key", True, ("cipher", "mode"), TEXT_MALFORMED, "zero-trust consensus",
              "unresolved claim (r6)"),
    field_row("claim", "value", True, ("AES-256-GCM", "AES-128-CBC"), TEXT_MALFORMED, "zero-trust consensus",
              "unresolved claim (r6)"),
    field_row("claim", "claim_type", False, ("security_assertion",), TEXT_MALFORMED + ("unknown-type",),
              "zero-trust consensus", "unresolved claim (r6)"),
    field_row("claim", "evidence", False, ("", " ", "cited"), (None,) + WRONG_KIND, "zero-trust consensus",
              "unresolved claim (r6)"),
    # Call arguments.
    field_row("argument", "candidate", True, (CANDIDATE, OTHER_CANDIDATE), TEXT_MALFORMED,
              "every binding", "every binding fails (r1)"),
    field_row("argument", "scope", True, (SCOPE, "bead:another-task"), TEXT_MALFORMED,
              "current or history", "r7: no record can be current or history, so targeted records are invalid"),
    field_row("argument", "zero_trust_required", False, (True, False), (None, "", "false", "true", 0, 1, [], {}),
              "zero-trust consensus", "absent is the opt-in default (not required); r7: any non-boolean is required"),
    field_row("argument", "adjudications", False, (None, []), ({}, "", 7, "x", {"adj-ext": "record"}),
              "every adjudication", "r7: unresolved for every input, possible quarantine, blocks"),
    field_row("argument", "dispatch_records", False, (None, []), ({}, "", 7, "x"),
              "every binding", "every attempted binding fails (r2)"),
)
TABLE_SHAPES = ("accepted", "recommended", "tripwire-held", "peer-held", "quarantined", "local-v2")
TABLE_ADJUDICATIONS = ("none", "accepting", "quarantining", "rejecting")
STATUS_RANK = {"ready": 0, "partial": 1, "blocked": 2}


def table_scenario(shape: str, explicit: str | None, adjudication_kind: str, external: bool = True,
                   consensus_mode: str = "off", peers_external: bool = False) -> dict:
    """Two primaries (internal unless ``peers_external``) and the lane ``ext`` under one shape and override.

    ``external`` and ``peers_external`` give the internal-only, external-only and mixed topologies; under
    ``consensus_mode`` "matching" or "dissent" consensus is required and ext's second claim matches or dissents.
    """

    if shape == "accepted":
        ext = returned("ext", "d-ext")
    elif shape == "recommended":
        ext = recommended_primary("ext", "d-ext")
    elif shape == "tripwire-held":
        ext = tripwire_held("ext", "d-ext")
    elif shape == "peer-held":
        ext = tripwire_held("ext", "d-ext", hold_reasons=[TRIPWIRE, PEER])
    elif shape == "quarantined":
        ext = returned("ext", "d-ext", disposition="quarantined")
    else:
        ext = returned("ext", "d-ext", **LOCAL_V2_VALID)
    ext["external"] = external
    if explicit is not None:
        ext["synthesis_use"] = explicit
    internal = [returned("opus", "d-opus", external=peers_external),
                returned("chatgpt", "d-chatgpt", external=peers_external)]
    records = [CONTROL, dispatch("d-chatgpt", "chatgpt_pro_browser_master_reviewer"),
               dispatch("d-ext", GLM_COMPACT if shape == "local-v2" else "codex_architecture_critic")]
    adjudications = {
        "none": [],
        "accepting": [adjudication("adj-ext", "d-ext")],
        "quarantining": [adjudication("adj-ext", "d-ext", decision="quarantined", evidence=[])],
        "rejecting": [adjudication("adj-ext", "d-ext", decision="rejected", evidence=[])],
    }[adjudication_kind]
    arguments = {"candidate": CANDIDATE, "scope": SCOPE}
    if consensus_mode != "off":
        arguments["zero_trust_required"] = True
        for entry in internal:
            entry["zero_trust_claims"] = [copy.deepcopy(AUTH), copy.deepcopy(CIPHER)]
        ext["zero_trust_claims"] = [copy.deepcopy(AUTH),
                                    copy.deepcopy(OTHER_CIPHER if consensus_mode == "dissent" else CIPHER)]
    return {"inputs": [*internal, ext], "records": records, "adjudications": adjudications, "arguments": arguments}


def table_mutation(scenario: dict, row: dict, value: object, lane_index: int = 2) -> dict | None:
    """The scenario with ``row``'s field set to ``value``, or None when the scenario has no such field."""

    mutated = copy.deepcopy(scenario)
    where, field = row["where"], row["field"]
    entry = mutated["inputs"][lane_index]
    if callable(value):
        value = value(entry)
    elif isinstance(value, list) and value and callable(value[0]):
        value = [value[0](entry)]

    if value is AGREES:
        value = DERIVED_IDENTITY[mutated["records"][2]["executor"]][field]

    def put(container: dict, key: str) -> None:
        if value == ABSENT and isinstance(value, str):
            container.pop(key, None)
        else:
            container[key] = copy.deepcopy(value)

    records = mutated["adjudications"]
    if where == "input":
        put(entry, field)
    elif where == "input-record":
        mutated["inputs"][lane_index] = copy.deepcopy(value)
    elif where in ("adjudication", "adjudication-record", "evidence", "authority"):
        if not records:
            return None
        if where == "adjudication":
            put(records[0], field)
        elif where == "adjudication-record":
            records[0] = copy.deepcopy(value)
        elif where == "evidence":
            if not records[0]["supporting_evidence"]:
                return None
            put(records[0]["supporting_evidence"][0], field)
    elif where == "extra-adjudication":
        if not (value == ABSENT and isinstance(value, str)):
            records.append(copy.deepcopy(value))
    elif where == "dispatch":
        put(mutated["records"][2], field)
    elif where == "dispatch-record":
        mutated["records"][2] = copy.deepcopy(value)
    elif where == "claim":
        claims = mutated["inputs"][2].get("zero_trust_claims")
        if not claims:
            return None
        put(claims[1], field)
    elif where == "argument":
        absent = value == ABSENT and isinstance(value, str)
        if field == "adjudications":
            mutated["adjudications"] = None if absent else copy.deepcopy(value)
        elif field == "dispatch_records":
            mutated["records"] = None if absent else copy.deepcopy(value)
        elif value == ABSENT and isinstance(value, str):
            mutated["arguments"].pop(field, None)
        else:
            mutated["arguments"][field] = copy.deepcopy(value)
    return mutated


def run_table(scenario: dict) -> dict:
    return evaluate_synthesis_inputs(scenario["inputs"], dispatch_records=scenario["records"],
                                     adjudications=scenario["adjudications"], **scenario["arguments"])


def lane_level(summary: dict) -> int:
    """0 primary, 1 salvage-only with nothing overridden, 2 anything that keeps the result from ready."""

    use = summary["synthesis_use"]
    if use == "primary":
        return 0
    if use == "salvage-only" and not summary["overridden_restrictions"] and not summary.get("adjudication_unresolved"):
        return 1
    return 2


def restriction(result: dict) -> dict:
    summaries = result["input_summaries"]
    return {
        "status": STATUS_RANK.get(result["status"], 2),
        "levels": tuple(lane_level(item) for item in summaries),
        "quarantined": frozenset(index for index, item in enumerate(summaries) if item["quarantine_in_force"]),
        "external_block": EXTERNAL_BLOCK in result["blocked_reasons"],
        "domains": result["zero_trust_consensus"]["independent_trust_domain_count"],
    }


def most_restrictive(restrictions: list) -> dict:
    return {
        "status": max(item["status"] for item in restrictions),
        "levels": tuple(max(levels) for levels in zip(*(item["levels"] for item in restrictions))),
        "quarantined": frozenset().union(*(item["quarantined"] for item in restrictions)),
        "external_block": any(item["external_block"] for item in restrictions),
        "domains": min(item["domains"] for item in restrictions),
    }


def less_restrictive(candidate: dict, reference: dict) -> list:
    """How ``candidate`` is less restrictive than ``reference`` (empty when it is not)."""

    reasons = []
    if candidate["status"] < reference["status"]:
        reasons.append("status")
    for index, (mine, theirs) in enumerate(zip(candidate["levels"], reference["levels"])):
        if mine < theirs:
            reasons.append(f"input {index} use")
    if reference["quarantined"] - candidate["quarantined"]:
        reasons.append("quarantine")
    if reference["external_block"] and not candidate["external_block"]:
        reasons.append("external block")
    if candidate["domains"] > reference["domains"]:
        reasons.append("trust domains")
    return reasons


def field_findings(scenario: dict, row: dict, lane_index: int = 2) -> list:
    """Malformed values of ``row`` that leave the result less restrictive than the most restrictive
    well-formed value (the unmutated scenario included)."""

    references = [restriction(run_table(scenario))]
    for value in row["well_formed"]:
        mutated = table_mutation(scenario, row, value, lane_index)
        if mutated is None:
            return []
        references.append(restriction(run_table(mutated)))
    envelope = most_restrictive(references)
    findings = []
    for value in row["malformed"]:
        mutated = table_mutation(scenario, row, value, lane_index)
        if mutated is None:
            return []
        reasons = less_restrictive(restriction(run_table(mutated)), envelope)
        if reasons:
            findings.append((row["where"], row["field"], value, reasons))
    return findings


class FieldTableTests(unittest.TestCase):
    """Every restriction-bearing field is in the table, and no malformed value of it weakens the result."""

    def test_table_names_every_field_read(self) -> None:
        # Round 8: every raw field read happens in the normalization module (RawReadEliminationTests proves
        # that synthesis.py and adjudication.py read none), so the table is checked against that module.
        import ast
        from cwo_core import synthesis_inputs as module
        tree = ast.parse((ROOT / "scripts" / "cwo_core" / "synthesis_inputs.py").read_text(encoding="utf-8"))
        # Trusted configuration is excluded; public summary parsing is not.
        skipped = set(module.CONFIGURATION_PARSERS)
        read: set[str] = set()

        def scan(node: ast.AST) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.ClassDef)) and child.name in skipped:
                    continue
                if isinstance(child, ast.Call) and child.args:
                    first = child.args[0]
                    name = child.func.attr if isinstance(child.func, ast.Attribute) else getattr(child.func, "id", "")
                    if name == "get" and isinstance(first, ast.Constant) and isinstance(first.value, str):
                        read.add(first.value)
                    if name in ("_text_field", "_digest_field", "_use_field") and len(child.args) > 1:
                        second = child.args[1]
                        if isinstance(second, ast.Constant) and isinstance(second.value, str):
                            read.add(second.value)
                if isinstance(child, ast.Subscript) and isinstance(child.slice, ast.Constant) \
                        and isinstance(child.slice.value, str):
                    read.add(child.slice.value)
                if isinstance(child, ast.Compare) and isinstance(child.left, ast.Constant) \
                        and isinstance(child.left.value, str) and any(isinstance(op, (ast.In, ast.NotIn))
                                                                      for op in child.ops):
                    read.add(child.left.value)
                scan(child)

        scan(tree)
        # Fields read through the module's field-name constants.
        for constant in (module.BOUNDARY_FIELDS, module.PROVIDER_LABEL_FIELDS, module.LOCAL_V2_MARKER_FIELDS,
                         module.ZERO_TRUST_CLAIM_FIELDS, module.ROLE_LABEL_FIELDS, module.BINDING_FIELDS,
                         module.RECORD_IDENTITY_CLAIMS, [name for name, _ in module.LOCAL_V2_EVIDENCE_FIELDS]):
            read |= set(constant)
        # "rule" is the authority row's field; the rest are values compared against, not fields.
        tabled = {row["field"] for row in (*FIELD_TABLE, *SUMMARY_FIELD_TABLE)} | {"rule"}
        values = {"boundary-tainted", "."}
        self.assertEqual(sorted(read - tabled - values), [])
        self.assertTrue({"disposition", "decision", "dispatch_id", "local_http_status", "provider_family"} <= read)

    def test_rows_are_well_formed(self) -> None:
        for row in FIELD_TABLE:
            with self.subTest(where=row["where"], field=row["field"]):
                self.assertTrue(row["malformed"])
                self.assertTrue(row["disposition"])
                for value in row["malformed"]:
                    self.assertFalse(any(value == other and type(value) is type(other) for other in row["well_formed"]),
                                     value)
                if row["where"].endswith("-record"):
                    self.assertNotIn(ABSENT, [*row["well_formed"], *row["malformed"]])

    def test_malformed_field_is_never_less_restrictive(self) -> None:
        # A reduced product; the fuzz probe runs every shape, override, topology and lane. Round 8 adds
        # required consensus with internal-only, external-only and mixed lanes, and a local critic v2 lane.
        baselines = (
            ("accepted", None, "quarantining", True, "off"),
            ("accepted", "salvage-only", "quarantining", True, "off"),
            ("accepted", "salvage-only", "accepting", True, "off"),
            ("peer-held", None, "accepting", True, "off"),
            ("tripwire-held", None, "accepting", False, "off"),
            ("recommended", "primary", "accepting", True, "off"),
            ("accepted", None, "none", True, "dissent"),
            ("accepted", None, "none", False, "dissent"),
            ("accepted", None, "none", True, "dissent", True),
            ("local-v2", None, "none", False, "dissent"),
            ("local-v2", None, "none", True, "dissent"),
        )
        for baseline in baselines:
            scenario = table_scenario(*baseline)
            for row in FIELD_TABLE:
                with self.subTest(baseline=baseline, where=row["where"], field=row["field"]):
                    self.assertEqual(field_findings(scenario, row), [])
        scenario = table_scenario("accepted", None, "quarantining", True, "dissent")
        for row in FIELD_TABLE:
            if row["where"] in ("input", "input-record"):
                with self.subTest(lane="opus", where=row["where"], field=row["field"]):
                    self.assertEqual(field_findings(scenario, row, lane_index=0), [])

    def test_inputs_that_are_not_a_list_block(self) -> None:
        for value in (None, {}, "x", 7):
            with self.subTest(inputs=value):
                result = evaluate_synthesis_inputs(value, dispatch_records=[], adjudications=[],
                                                   candidate=CANDIDATE, scope=SCOPE)
                self.assertEqual(result["status"], "blocked")
                self.assertIn("inputs must be a list; nothing in it can be evaluated", result["blocked_reasons"])


if __name__ == "__main__":
    unittest.main()
