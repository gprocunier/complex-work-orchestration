"""Autonomous host acceptance and independently verified closure evidence.

The embedding product host pins the decision adapter at bootstrap, as it does
for qualified adjudication. Workers submit evidence, never an adapter or an
approval file. Host code under the same OS user remains outside this boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Callable

from .errors import CWOPolicyError
from .host_records import configured_store
from .peer_review import PEER_REVIEW_HOLDS, pending_evaluation_sha256
from .peer_review_identity import _recorded_dispatch, _registered_model, validate_separation
from .returns import make_acceptance_decision
from . import policy
from .policy import load_policy
from .policy_schema import strict_json_loads


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise CWOPolicyError("host acceptance: " + message)


def _copy(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True, allow_nan=False))


def _policy_sha256() -> str:
    names = ("acceptance-policy", "contracting-controls", "provider-registry", "executor-registry",
             "return-tripwires", "synthesis-policy", "share-boundaries")
    return pending_evaluation_sha256({name: _current_policy(name) for name in names})


def _current_policy(name):
    try:
        current = strict_json_loads((policy.POLICY_DIR / (name + ".yaml")).read_text(encoding="utf-8"))
        cached = load_policy(name)
    except (OSError, ValueError, UnicodeError, SystemExit) as failure:
        raise CWOPolicyError("host acceptance: current evaluation policy is unavailable or malformed") from failure
    _need(pending_evaluation_sha256(current) == pending_evaluation_sha256(cached),
          "current policy cache differs from source")
    return current


@dataclass(frozen=True)
class HostAdjudicationDecision:
    """One decision returned by the host-selected autonomous CWO adapter."""

    decision: str
    rationale: str
    control_id: str


class HostAcceptancePipeline:
    """Evaluate and adjudicate a received return; no effect is enabled here."""

    def __init__(self, control: Callable, *, store=None):
        _need(callable(control), "the host must pin its autonomous adjudication adapter")
        self._control = control
        self._store = configured_store() if store is None else store

    def accept(self, text: str, *, bead_id: str, dispatch_id: str,
               database_identity: dict, peer_review_record: dict | None = None) -> str:
        store = self._store
        _need(len(store.find("workspace-database-identity", database_identity=database_identity)) == 1,
              "database identity was not established by host workspace initialization")
        returned = hashlib.sha256(text.encode("utf-8")).hexdigest()
        dispatch = store.require_dispatch(dispatch_id)
        observed, identity, _ = _recorded_dispatch(dispatch_id)
        _registered_model(identity)
        _need(observed == dispatch, "configured store differs from host pipeline store")
        receipt = store.require_return(dispatch_id, returned)
        _need(dispatch.get("dispatch_role") == "executor", "an executor dispatch is required")
        _need(dispatch.get("bead_id") == bead_id, "dispatch task does not match")
        _need(receipt["dispatch_record_sha256"] == dispatch["_record_sha256"], "return dispatch differs")
        policy_sha = _policy_sha256()
        inputs = _host_inputs(dispatch, bead_id, dispatch_id)
        pending, evaluation = _evaluate(text, inputs, peer_review_record)
        required = list(pending["hold_reasons"])
        _eligible(evaluation)
        _need(set(required) <= PEER_REVIEW_HOLDS, "unresolved evidence or task holds require their qualified pipeline")
        frozen = _copy(evaluation)
        decision = self._control(_copy(evaluation))
        _need(type(decision) is HostAdjudicationDecision and decision.decision == "accepted",
              "autonomous adjudication did not accept")
        _need(type(decision.rationale) is str and 0 < len(decision.rationale.strip()) <= 2048,
              "adjudication rationale is missing or over bound")
        _need(type(decision.control_id) is str and 0 < len(decision.control_id) <= 128,
              "host adjudication identity is missing or over bound")
        _need(policy_sha == _policy_sha256(), "evaluation policy changed during adjudication")
        _need(dispatch == store.require_dispatch(dispatch_id)
              and receipt == store.require_return(dispatch_id, returned), "dispatch or receipt changed")
        if peer_review_record is not None:
            _need(evaluation == make_acceptance_decision(text, peer_review_status="passed",
                peer_review_record=peer_review_record,
                peer_review_reviewer=peer_review_record.get("reviewer_identity"), **inputs),
                "review evidence changed during adjudication")
        digest = pending_evaluation_sha256(frozen)
        context = dict(bead_id=bead_id, dispatch_id=dispatch_id, return_sha256=returned,
                       evaluation_sha256=digest)
        evaluation_record = store.write_record("evaluation", **context, evaluation=frozen,
            pending_evaluation=pending, return_text=text, policy_sha256=policy_sha,
            dispatch_record_sha256=dispatch["_record_sha256"], return_record_sha256=receipt["_record_sha256"])
        adjudication_record = store.write_record("adjudication", **context, decision="accepted",
            rationale=decision.rationale, control_id=decision.control_id, evaluation_record=evaluation_record)
        cleared = {}
        for hold in required:
            cleared[hold] = store.write_record("hold-clearance", **context, hold=hold,
                evaluation_record=evaluation_record, peer_review_record=frozen["peer_review_record"],
                peer_review_separation=frozen["peer_review_separation"])
        acceptance_id = store.write_acceptance(**context, database_identity=database_identity,
            adjudication_result="accepted", required_holds=required, cleared_holds=cleared,
            evaluation_record=evaluation_record, adjudication_record=adjudication_record)
        store.record_audit_event({"event_type": "host_acceptance_decided",
            "acceptance_record_sha256": acceptance_id, "adjudication_record_sha256": adjudication_record,
            "host_control_id": decision.control_id, **context})
        return acceptance_id


def _host_inputs(dispatch, bead_id, dispatch_id):
    metadata = _copy(dispatch.get("evaluation_metadata") or {})
    forbidden = {"text", "bead_id", "dispatch_id", "packet_sha256", "executor", "provider_key", "peer_review_status",
                 "peer_review_record", "peer_review_reviewer"}
    _need(not forbidden.intersection(metadata), "dispatch metadata overrides host identity or review state")
    return {**metadata, "bead_id": bead_id, "dispatch_id": dispatch_id,
            "packet_sha256": dispatch.get("packet_sha256"), "executor": dispatch.get("executor"), "provider_key": dispatch.get("provider_key")}


def _evaluate(text, inputs, review):
    pending = make_acceptance_decision(text, peer_review_status="pending", **inputs)
    if review is None:
        return pending, make_acceptance_decision(text, **inputs)
    result = make_acceptance_decision(text, peer_review_status="passed", peer_review_record=review,
        peer_review_reviewer=review.get("reviewer_identity"), **inputs)
    return pending, result


def _eligible(evaluation: dict) -> None:
    _need(evaluation.get("verdict") == "accept" and evaluation.get("accepted_for_use") is True
          and evaluation.get("implementation_blocked") is False and evaluation.get("evidence_use_hold") is False
          and evaluation.get("hold_reasons") == [] and evaluation.get("hard_disqualifiers") == []
          and evaluation.get("quarantine_recommended") is False,
          "evaluation is held, rejected or not globally accepted")


def _context(record: dict, expected: dict) -> None:
    _need(all(record.get(name) == value for name, value in expected.items()), "record context does not match")


def require_acceptance(store, acceptance_record: str, *, bead_id: str, return_sha256: str,
                       evaluation_sha256: str, database_identity: dict) -> dict:
    """Read only: check exact task, database and every independently anchored input."""
    accepted = store.get(acceptance_record, record_type="acceptance-decision")
    expected = dict(bead_id=bead_id, return_sha256=return_sha256, evaluation_sha256=evaluation_sha256)
    _context(accepted, expected)
    _need(accepted.get("database_identity") == database_identity, "database identity does not match acceptance")
    _need(accepted.get("adjudication_result") == "accepted", "acceptance decision is not accepted")
    expected["dispatch_id"] = accepted["dispatch_id"]
    recorded, evaluation, pending = _verified_evaluation(store, accepted, expected)
    _verified_receipts(store, recorded, expected)
    adjudication = store.get(accepted.get("adjudication_record"), record_type="adjudication")
    _context(adjudication, expected)
    _need(adjudication.get("decision") == "accepted"
          and adjudication.get("evaluation_record") == recorded["_record_sha256"], "adjudication does not accept evaluation")
    required, clearances = _required_clearances(accepted, pending)
    for hold in required:
        clearance = store.get(clearances[hold], record_type="hold-clearance")
        _context(clearance, expected)
        _need(clearance.get("hold") == hold and clearance.get("evaluation_record") == recorded["_record_sha256"],
              "hold clearance targets another hold or evaluation")
        _verified_peer_clearance(store, clearance, evaluation, pending, expected)
    store.require_audit_event("host_acceptance_decided", acceptance_record_sha256=acceptance_record,
        adjudication_record_sha256=accepted["adjudication_record"], host_control_id=adjudication["control_id"], **expected)
    return accepted


def _verified_evaluation(store, accepted, expected):
    recorded = store.get(accepted.get("evaluation_record"), record_type="evaluation")
    _context(recorded, expected)
    evaluation, pending = recorded.get("evaluation"), recorded.get("pending_evaluation")
    _need(type(evaluation) is dict and type(pending) is dict, "evaluation snapshots are missing")
    _need(pending_evaluation_sha256(evaluation) == expected["evaluation_sha256"], "evaluation digest does not match")
    _need(recorded.get("policy_sha256") == _policy_sha256(), "evaluation policy is stale")
    _eligible(evaluation)
    text = recorded.get("return_text")
    _need(type(text) is str and hashlib.sha256(text.encode("utf-8")).hexdigest() == expected["return_sha256"],
          "received return snapshot differs")
    dispatch = store.require_dispatch(expected["dispatch_id"])
    inputs = _host_inputs(dispatch, expected["bead_id"], expected["dispatch_id"])
    actual_pending, actual_evaluation = _evaluate(text, inputs, evaluation.get("peer_review_record"))
    _need(actual_pending == pending and actual_evaluation == evaluation,
          "recorded evaluation differs from current host-metadata evaluation")
    return recorded, evaluation, pending


def _verified_receipts(store, recorded, expected):
    dispatch = store.require_dispatch(expected["dispatch_id"])
    observed, identity, _ = _recorded_dispatch(expected["dispatch_id"])
    _registered_model(identity)
    _need(observed == dispatch, "configured store differs from closure store")
    receipt = store.require_return(expected["dispatch_id"], expected["return_sha256"])
    _need(dispatch.get("bead_id") == expected["bead_id"] and dispatch.get("dispatch_role") == "executor",
          "executor task or role differs")
    _need(recorded.get("dispatch_record_sha256") == dispatch["_record_sha256"]
          and recorded.get("return_record_sha256") == receipt["_record_sha256"]
          and receipt["dispatch_record_sha256"] == dispatch["_record_sha256"], "evaluation receipt binding differs")


def _required_clearances(accepted, pending):
    required, clearances = accepted.get("required_holds"), accepted.get("cleared_holds")
    _need(type(required) is list and type(clearances) is dict and len(required) == len(set(required))
          and set(required) == set(pending.get("hold_reasons", [])) == set(clearances),
          "required hold clearance is incomplete or inconsistent")
    _need(set(required) <= PEER_REVIEW_HOLDS, "unsupported unresolved hold")
    return required, clearances


def _verified_peer_clearance(store, clearance, evaluation, pending, expected):
    record = clearance.get("peer_review_record")
    separation = clearance.get("peer_review_separation")
    _need(record == evaluation.get("peer_review_record") and separation == evaluation.get("peer_review_separation"),
          "hold clearance review does not match evaluation")
    _need(type(record) is dict and record.get("decision") == "passed"
          and record.get("return_sha256") == expected["return_sha256"]
          and record.get("evaluation_sha256") == pending_evaluation_sha256(pending), "hold review target differs")
    reviewer = record["reviewer_identity"]
    validate_separation(reviewer, separation)
    _verify_review_dispatch(store, reviewer, record, separation, expected)


def _verify_review_dispatch(store, reviewer, record, separation, expected):
    from .peer_review_identity import separation_level
    own = store.require_dispatch(expected["dispatch_id"])
    review = store.require_dispatch(reviewer["dispatch_id"])
    observed = {name: own.get(name) for name in reviewer}
    observed_review = {name: review.get(name) for name in reviewer}
    _need(observed_review == reviewer and review.get("dispatch_role") == "peer-review"
          and review.get("review_target") == {"dispatch_id": expected["dispatch_id"],
              "return_sha256": expected["return_sha256"], "evaluation_sha256": record["evaluation_sha256"]},
          "verified peer review dispatch targets another evaluation")
    store.require_return(reviewer["dispatch_id"], pending_evaluation_sha256(record))
    _need(separation["executor_identity"] == observed
          and separation["executor_dispatch_sha256"] == own["_record_sha256"]
          and separation["reviewer_dispatch_sha256"] == review["_record_sha256"]
          and separation["level"] == separation_level(observed, reviewer, own["session_id"], review["session_id"]),
          "verified peer separation differs")


def record_received_evaluation(text: str, evaluation: dict) -> str | None:
    """The CLI may report legacy evidence; only received host evidence is recorded.

    Missing legacy dispatches produce no authority. Once a host dispatch exists,
    a mismatched return or identity refuses instead of falling back to legacy.
    """
    store = configured_store()
    dispatch_id = evaluation.get("dispatch_id")
    if not dispatch_id or not store.find("dispatch", dispatch_id=dispatch_id):
        return None
    dispatch = store.require_dispatch(dispatch_id)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    receipt = store.require_return(dispatch_id, digest)
    _need(dispatch.get("bead_id") == evaluation.get("bead_id"), "evaluated task differs from host dispatch")
    _need(dispatch.get("executor") == evaluation.get("executor"), "evaluated executor differs from host dispatch")
    return store.write_record("evaluation", dispatch_id=dispatch_id, bead_id=evaluation.get("bead_id"),
        return_sha256=digest, evaluation_sha256=pending_evaluation_sha256(evaluation),
        evaluation=_copy(evaluation), policy_sha256=_policy_sha256(),
        dispatch_record_sha256=dispatch["_record_sha256"], return_record_sha256=receipt["_record_sha256"])
