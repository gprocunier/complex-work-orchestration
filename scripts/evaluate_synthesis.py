#!/usr/bin/env python3
"""Combine recorded critic evaluations and operator Codex evidence for architect review."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from cwo_core.adjudication_binding import _evaluation_disposition
from cwo_core.errors import CWOPolicyError
from cwo_core.host_acceptance import (
    _current_policy, _policy_sha256, _source_context, _verify_review_dispatch, require_current_advisory_holds,
)
from cwo_core.host_records import configured_store
from cwo_core.host_return_intake import MAX_RETURN_BYTES
from cwo_core.peer_review import pending_evaluation_sha256, validate_peer_review_request
from cwo_core.policy import executor_config
from cwo_core.policy_schema import strict_json_loads
from cwo_core.return_risk import procedural_hold_metadata
from cwo_core.returns import make_acceptance_decision, mark_advisory_return
from cwo_core.synthesis import evaluate_synthesis_inputs
from cwo_core.synthesis_inputs import digest, text


def _read_bytes(path):
    with path.open("rb") as stream:
        data = stream.read(MAX_RETURN_BYTES + 1)
    if len(data) > MAX_RETURN_BYTES:
        raise ValueError(f"{path.name} exceeds the input size limit")
    return data


def _read_json(path):
    return strict_json_loads(_read_bytes(path).decode("utf-8"))


def _object(value, label):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _list(value, label):
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a JSON list")
    return value


def _input_file(item, key, directory):
    value = text(item.get(key))
    if value is None:
        raise ValueError(f"each input must name its {key} file")
    return directory / value


def _evaluation_input(store, item, directory):
    use_record = "evaluation_record_sha256" in item
    if ("evaluation" in item) == use_record:
        raise ValueError("each input must provide exactly one of evaluation or evaluation_record_sha256")
    if use_record:
        record = store.get(item["evaluation_record_sha256"], record_type="evaluation")
        return _object(record.get("evaluation"), "recorded evaluation"), record
    return _object(_read_json(_input_file(item, "evaluation", directory)), "evaluation"), None


def _recorded_evaluation(store, dispatch, receipt, evaluation, policy_sha256, selected_record):
    evaluation_digest = pending_evaluation_sha256(evaluation)
    binding = dict(dispatch_id=dispatch["dispatch_id"],
        return_sha256=receipt["return_sha256"], evaluation_sha256=evaluation_digest,
        dispatch_record_sha256=dispatch["_record_sha256"], return_record_sha256=receipt["_record_sha256"],
        policy_sha256=policy_sha256)
    if selected_record is None:
        records = store.find("evaluation", **binding)
    else:
        matches = all(selected_record.get(name) == value for name, value in binding.items())
        records = [selected_record] if matches else []
    if not records:
        raise ValueError("evaluation does not match a current recorded evaluation of this return")
    if not any(isinstance(record.get("evaluation"), dict)
               and pending_evaluation_sha256(record["evaluation"]) == evaluation_digest for record in records):
        raise ValueError("recorded evaluation contents do not match")
    if any(evaluation.get(name) != dispatch.get(name)
           for name in ("dispatch_id", "bead_id", "executor", "packet_sha256", "provider_key")):
        raise ValueError("evaluation identity does not match its recorded dispatch")
    require_current_advisory_holds(store, dispatch, receipt, evaluation)
    return evaluation_digest


def _verify_passed_review(store, dispatch, evaluation, return_sha256):
    reviewer = evaluation.get("peer_review_reviewer")
    record = validate_peer_review_request("passed", reviewer, evaluation.get("peer_review_record"))
    if record["return_sha256"] != return_sha256:
        raise ValueError("peer review does not bind the selected return")
    _verify_review_dispatch(store, reviewer, record, evaluation["peer_review_separation"],
        dict(dispatch_id=dispatch["dispatch_id"], return_sha256=return_sha256))


def _preserve_peer_requirement(store, dispatch, evaluation, return_sha256):
    metadata = dispatch["evaluation_metadata"]
    required = evaluation.get("peer_review_required")
    conflicts = _list(metadata.get("provider_conflict_domains", []), "recorded provider conflict domains")
    if required is False and metadata.get("peer_review_required", False) is False and not conflicts:
        return evaluation
    if required is True and set(conflicts).issubset(evaluation.get("provider_conflict_domains", [])):
        if evaluation.get("peer_review_status") == "passed":
            _verify_passed_review(store, dispatch, evaluation, return_sha256)
        return evaluation
    # Earlier evaluations can omit a dispatch requirement. Restore the original
    # peer hold using the return evaluator's policy before any synthesis use.
    pending = procedural_hold_metadata(peer_required=True, peer_review_status="pending",
                                       provider_conflict_domains=conflicts)
    holds = list(dict.fromkeys([*evaluation["hold_reasons"], *pending["hold_reasons"]]))
    classification = evaluation.get("hold_classification")
    if classification in (None, "none"):
        classification = pending["hold_classification"]
    recommendation = evaluation["recommended_synthesis_use"]
    return dict(evaluation, implementation_blocked=True, evidence_use_hold=True, accepted_for_use=False,
                hold_reasons=holds, hold_classification=classification,
                recommended_synthesis_use="open-risk" if recommendation == "primary" else recommendation)


def _lane_input(item, evaluation, lane):
    # Carry the evaluator's holds and provider metadata through to the existing
    # synthesis policy alongside the operator's local claims.
    disposition = _evaluation_disposition(evaluation)
    if evaluation["verdict"] == "partial-accept" and not evaluation["evidence_use_hold"]:
        disposition = "salvage-only"
    entry = dict(evaluation, lane=lane, disposition=disposition, external=evaluation.get("provider_external"))
    if "zero_trust_claims" in item:
        entry["zero_trust_claims"] = item["zero_trust_claims"]
    return entry


def _primary_use_request(item, evaluation, exact_return):
    if "synthesis_use" not in item:
        return {}
    if item["synthesis_use"] != "primary":
        raise ValueError('recorded synthesis_use must be "primary" when supplied')
    if not exact_return:
        raise ValueError("a primary use request must match the exact host return receipt")
    if (evaluation["verdict"] != "accept" or evaluation["accepted_for_use"] is not True
            or evaluation["screening_eligible"] is not True or evaluation["evidence_use_hold"] is not False
            or evaluation["implementation_blocked"] is not False
            or evaluation["recommended_synthesis_use"] != "salvage-only"):
        raise ValueError("a primary use request requires an accepted salvage-only evaluation without a use hold")
    return {"synthesis_use": "primary"}


def _recorded_lane(store, item, directory, candidate, scope, policy_sha256):
    evaluation, selected_record = _evaluation_input(store, item, directory)
    raw = _read_bytes(_input_file(item, "return", directory))
    return _project_recorded_lane(store, item, evaluation, selected_record, hashlib.sha256(raw).hexdigest(),
                                  candidate, scope, policy_sha256)


def _require_protected_capture(dispatch, receipt, context):
    if receipt.get("capture_provenance") != "host-capture-v1":
        raise ValueError("protected synthesis requires an original host-captured return")
    if dispatch.get("stage") != "observed":
        raise ValueError("protected synthesis requires an observed executor dispatch")
    if context is None and "source_context" in dispatch["evaluation_metadata"]:
        raise ValueError("protected synthesis dispatch context is incomplete")


def _project_recorded_lane(store, item, evaluation, selected_record, return_sha256, candidate, scope,
                           policy_sha256, *, protected=False):
    dispatch = store.require_dispatch(evaluation.get("dispatch_id"))
    if dispatch["dispatch_role"] != "executor":
        raise ValueError("a critic return must come from a recorded executor dispatch")
    receipt = store.require_return(dispatch["dispatch_id"], return_sha256)
    if selected_record is not None and receipt["return_sha256"] != return_sha256:
        raise ValueError("selected return does not match the exact host return receipt")
    evaluation_digest = _recorded_evaluation(store, dispatch, receipt, evaluation, policy_sha256, selected_record)
    context = _source_context(dispatch)
    if protected:
        _require_protected_capture(dispatch, receipt, context)
    if context is not None and (context["candidate"], context["scope"]) != (candidate, scope):
        raise ValueError("recorded dispatch candidate or scope differs from the synthesis selection")
    binding = dict(record_type="cwo-dispatch-record", version=1,
        dispatch_id=dispatch["dispatch_id"], executor=dispatch["executor"], return_sha256=return_sha256,
        candidate=candidate, provider_key=dispatch["provider_key"], provider_family=dispatch["provider"])
    provenance = dict(dispatch_id=dispatch["dispatch_id"], return_sha256=return_sha256,
        dispatch_record_sha256=dispatch["_record_sha256"], return_record_sha256=receipt["_record_sha256"],
        evaluation_sha256=evaluation_digest, candidate_scope_basis="recorded" if context else "operator-selected")
    projected = _preserve_peer_requirement(store, dispatch, evaluation, return_sha256)
    entry = _lane_input(item, projected, dispatch["dispatch_id"])
    entry.update(_primary_use_request(item, projected, receipt["return_sha256"] == return_sha256))
    entry["return_sha256"] = return_sha256
    return entry, binding, provenance


def _operator_capture(item, candidate, scope):
    if set(item) - {"operator_codex", "return", "zero_trust_claims"}:
        raise ValueError("operator_codex input accepts only operator_codex, return and zero_trust_claims")
    origin = _object(item["operator_codex"], "operator_codex")
    if set(origin) != {"capture_id", "return_sha256", "candidate", "scope"}:
        raise ValueError("operator_codex requires capture_id, return_sha256, candidate and scope")
    capture_id = origin["capture_id"]
    if not isinstance(capture_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", capture_id):
        raise ValueError("operator_codex capture_id must be a bounded portable identifier")
    return_sha256 = digest(origin["return_sha256"])
    if return_sha256 is None:
        raise ValueError("operator_codex requires a lowercase SHA-256 return digest")
    if (origin["candidate"], origin["scope"]) != (candidate, scope):
        raise ValueError("operator_codex candidate or scope differs from the synthesis selection")
    return capture_id, return_sha256


def _operator_codex_lane(item, directory, candidate, scope):
    capture_id, return_sha256 = _operator_capture(item, candidate, scope)
    raw = _read_bytes(_input_file(item, "return", directory))
    if hashlib.sha256(raw).hexdigest() != return_sha256:
        raise ValueError("operator_codex return does not match its exact SHA-256 digest")
    executor = executor_config("codex_architecture_critic")
    if executor["dispatch_mode"] != "main_thread_review" or executor["external"]:
        raise ValueError("operator_codex requires the configured internal main-thread Codex critic")
    evaluation = make_acceptance_decision(raw.decode("utf-8"),
        executor=executor["key"], provider_key=executor["provider_key"], dispatch_mode=executor["dispatch_mode"],
        share_boundary="no-outside-sharing",
        job_description_label="contract-jd-architecture-reasoning")
    mark_advisory_return(evaluation)
    provenance = dict(source="operator-supplied-codex", candidate_scope_basis="operator-selected",
        capture_id=capture_id, executor=evaluation["executor"], provider_key=evaluation["provider_key"],
        return_sha256=return_sha256, evaluation_sha256=pending_evaluation_sha256(evaluation))
    entry = _lane_input(item, evaluation, capture_id)
    del entry["dispatch_id"]
    return entry, None, provenance


def _input_lane(store, item, directory, candidate, scope, policy_sha256):
    item = _object(item, "synthesis input")
    if "operator_codex" in item:
        return _operator_codex_lane(item, directory, candidate, scope)
    return _recorded_lane(store, item, directory, candidate, scope, policy_sha256)


def _route_signals(path):
    if path is None:
        return False, []
    route = _object(_read_json(path), "route")
    required = route.get("zero_trust_consensus_required")
    if not isinstance(required, bool):
        raise ValueError("route must declare whether zero-trust consensus is required")
    synthesis = _object(route.get("model_synthesis"), "route model_synthesis")
    return required, _list(synthesis.get("provider_conflict_flags"), "provider conflict flags")


def _synthesize(args):
    candidate = text(args.candidate)
    scope = text(args.scope)
    if candidate is None or scope is None:
        raise ValueError("candidate and scope must be nonempty")
    items = _list(_read_json(args.inputs), "synthesis inputs")
    adjudications = _list(_read_json(args.adjudications), "adjudications") if args.adjudications else None
    required, flags = _route_signals(args.route)
    store = configured_store()
    policy_sha256 = _policy_sha256()
    lanes = [_input_lane(store, item, args.inputs.parent, candidate, scope, policy_sha256) for item in items]
    capture_ids = [origin["capture_id"] for _, binding, origin in lanes if binding is None]
    capture_names = set(capture_ids)
    if len(capture_names) != len(capture_ids) or capture_names.intersection(
            binding["dispatch_id"] for _, binding, _ in lanes if binding is not None):
        raise ValueError("operator_codex capture_id must be unique in the input list")
    return _synthesis_result(lanes, adjudications, candidate, scope, required or args.zero_trust_required,
                             flags, provenance_basis="advisory")


def _synthesis_result(lanes, adjudications, candidate, scope, required, flags, *, provenance_basis):
    bindings = [binding for _, binding, _ in lanes if binding is not None]
    result = evaluate_synthesis_inputs([entry for entry, _, _ in lanes],
        dispatch_records=bindings, adjudications=adjudications,
        candidate=candidate, scope=scope, zero_trust_required=required)
    return dict(result, input_provenance=[provenance for _, _, provenance in lanes],
                provider_conflict_flags=flags, provenance_basis=provenance_basis, execution_permitted=False)


def _protected_lane_input(value):
    lane = _object(value, "protected synthesis lane")
    required = {"evaluation_record_sha256", "zero_trust_claims"}
    if set(lane) not in (required, required | {"synthesis_use"}):
        raise ValueError("protected synthesis lane requires an evaluation reference and explicit claims")
    if digest(lane["evaluation_record_sha256"]) is None:
        raise ValueError("protected synthesis lane requires a SHA-256 evaluation reference")
    if "synthesis_use" in lane and lane["synthesis_use"] != "primary":
        raise ValueError('protected synthesis_use must be "primary" when supplied')
    _list(lane["zero_trust_claims"], "protected synthesis lane claims")
    return lane


def _protected_lane(store, lane, candidate, scope, policy_sha256):
    selected = store.get(lane["evaluation_record_sha256"], record_type="evaluation")
    evaluation = _object(selected.get("evaluation"), "recorded evaluation")
    return _project_recorded_lane(store, lane, evaluation, selected, selected["return_sha256"],
                                  candidate, scope, policy_sha256, protected=True)


def validate_synthesis_approval(payload):
    """Read the panel selection shared by operator publication and host evaluation."""
    panel = _object(payload, "protected synthesis review")
    if set(panel) != {"candidate", "scope", "inputs", "adjudications"}:
        raise ValueError("protected synthesis review requires candidate, scope, inputs and adjudications")
    candidate, scope = text(panel["candidate"]), text(panel["scope"])
    if candidate is None or scope is None:
        raise ValueError("protected synthesis candidate and scope must be nonempty")
    inputs = [_protected_lane_input(lane) for lane in _list(panel["inputs"], "protected synthesis inputs")]
    adjudications = _list(panel["adjudications"], "protected synthesis adjudications")
    return candidate, scope, inputs, adjudications


def evaluate_protected_synthesis(store, payload):
    """Host handler for an operator-authorized panel resolved by the authority broker."""
    candidate, scope, inputs, adjudications = validate_synthesis_approval(payload)
    policy_sha256 = _policy_sha256()
    lanes = [_protected_lane(store, value, candidate, scope, policy_sha256) for value in inputs]
    _current_policy("zero-trust-consensus-policy")
    return _synthesis_result(lanes, adjudications, candidate, scope, True, [], provenance_basis="operator-authorized")


def _protected_request(args):
    if any(value is not None for value in (args.candidate, args.scope, args.adjudications, args.route)) or args.zero_trust_required:
        raise ValueError("protected review accepts only the operator-authorized review reference")
    from cwo_core.lead_authority import configured_authority_client

    return configured_authority_client().request("synthesis", args.protected_review)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sources = parser.add_mutually_exclusive_group(required=True)
    sources.add_argument("--inputs", type=Path,
                         help="Advisory report from return files with recorded evaluations or operator Codex evidence.")
    sources.add_argument("--protected-review", help="Operator-authorized review reference for the host controller.")
    parser.add_argument("--candidate", help="Candidate or plan revision under advisory review.")
    parser.add_argument("--scope", help="Adjudication scope for the advisory review.")
    parser.add_argument("--adjudications", type=Path, help="JSON list of bound return adjudication records.")
    parser.add_argument("--route", type=Path, help="Optional route_work.py JSON with consensus and conflict signals.")
    parser.add_argument("--zero-trust-required", action="store_true", help="Require cross-domain claim comparison.")
    try:
        args = parser.parse_args()
        result = _protected_request(args) if args.protected_review is not None else _synthesize(args)
    except (CWOPolicyError, ValueError, OSError, KeyError, TypeError, RecursionError) as failure:
        raise SystemExit(str(failure)) from failure
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
