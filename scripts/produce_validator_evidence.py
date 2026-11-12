"""Offline checked-command observations; successful closure stays unavailable."""
from __future__ import annotations

import contextlib
import copy
import os
from collections.abc import Callable
from typing import Any

import prepare_artifact_acceptance as artifacts
import prepare_validator_receipts as preparation
from cwo_core import candidate_identity as ci
from cwo_core import checked_command as cc
from cwo_core import requirement_baseline as rb

MAX_ERRORS = 16
MAX_ERROR_TEXT = 512


def _report() -> dict[str, Any]:
    return {
        "record_type": "cwo-validator-evidence-production", "version": 1,
        "state": "REFUSED", "observations_complete": False,
        **{key: False for key in preparation.AUTHORITY_FIELDS},
        "bindings": {}, "required_criterion_ids": [],
        "validator_evidence": [], "consumer_diagnostic": None,
        "candidate_checks": [], "checked_command_calls": 0,
        "unobserved_criterion_ids": [], "errors": [],
    }


def _error(report: dict[str, Any], prefix: str, error: Exception) -> None:
    if len(report["errors"]) < MAX_ERRORS:
        message = prefix + ": " + type(error).__name__ + ": " + str(error)
        report["errors"].append(message[:MAX_ERROR_TEXT])


def _input(root: Any, initial: Any, candidate: Any, bead: Any, commands: Any,
           amendments: Any) -> dict[str, Any]:
    if type(amendments) is tuple:
        preparation._need(len(amendments) <= preparation.MAX_AMENDMENTS, "too many amendments for reliable production")
        amendments = list(amendments)
    document = preparation._snapshot({
        "root": root, "baseline": initial, "candidate": candidate, "bead": bead,
        "commands": commands, "amendments": amendments,
    })
    preparation._root_text(document["root"])
    preparation._need(type(document["amendments"]) is list, "amendments must be a list for reliable production")
    preparation._need(len(document["amendments"]) <= preparation.MAX_AMENDMENTS, "too many amendments for reliable production")
    preparation._need(type(document["bead"]) is dict, "the Bead projection must be an object")
    preparation._need(type(document["commands"]) is dict, "commands must be a criterion mapping")
    preparation._need(len(document["commands"]) <= preparation.MAX_EVIDENCE, "too many command mappings for reliable production")
    return document


def _plan(document: dict[str, Any], chain: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    criteria = [item for item in chain["baseline"]["criteria"] if item["applicability"] == "required"]
    return _validator_plan(document, criteria)


def _validator_plan(document: dict[str, Any],
                    criteria: list[dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    preparation._need(set(document["commands"]) == {item["id"] for item in criteria},
                      "command mappings must exactly cover the required validator criteria")
    plan, receipts = [], set()
    for item in sorted(criteria, key=lambda item: item["id"]):
        contract = preparation._contract(item)
        normalized = preparation._normalized(document["commands"][item["id"]], document["root"])
        digest = preparation._sha(preparation._canonical(normalized))
        preparation._need(normalized["command_id"] == contract["command_id"],
                          "command ID differs from the independently declared criterion")
        preparation._need(digest == contract["spec_sha256"],
                          "command specification differs from the independently declared criterion")
        receipt = preparation._canonical([normalized["command_id"], digest])
        preparation._need(receipt not in receipts, "a command receipt is mapped more than once")
        receipts.add(receipt)
        plan.append((item["id"], normalized))
    return plan


def _component_bindings(document: dict[str, Any], chain: dict[str, Any]) -> dict[str, Any]:
    return {"root": document["root"], "resolved_baseline": chain,
            "candidate": document["candidate"],
            "bead_projection_digest": rb.record_digest(document["bead"])}


def _original_inventory(diagnostic: dict[str, Any], chain: dict[str, Any]) -> None:
    preparation._need(diagnostic["required_criterion_ids"] == rb.required_criterion_ids(chain["baseline"]),
                      "required reliability criterion membership differs from the original baseline")
    preparation._need([entry["id"] for entry in diagnostic["criteria"]]
                      == [item["id"] for item in chain["baseline"]["criteria"]],
                      "reliability criterion inventory differs from the original baseline")


def _artifact_plan(report: dict[str, Any], document: dict[str, Any], chain: dict[str, Any]) -> None:
    diagnostic = artifacts.prepare(
        document["root"], copy.deepcopy(document["baseline"]), copy.deepcopy(document["candidate"]),
        copy.deepcopy(document["bead"]), copy.deepcopy(document["amendments"]))
    report["artifact_diagnostic"] = copy.deepcopy(diagnostic)
    preparation._need(not diagnostic["errors"]
                      and diagnostic["candidate_checks"] == {"before": [], "after": []},
                      "original artifact reliability prerequisites were refused")
    preparation._need(preparation._canonical(diagnostic["bindings"])
                      == preparation._canonical(_component_bindings(document, chain)),
                      "artifact reliability bindings differ from the original context")
    _original_inventory(diagnostic, chain)
    for item in chain["baseline"]["criteria"]:
        if item["applicability"] == "required" and item["evidence_kind"] == "artifact":
            artifacts._predicate(copy.deepcopy(item), copy.deepcopy(document["candidate"]))


def _mixed_plan(report: dict[str, Any], document: dict[str, Any],
                chain: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    required = [item for item in chain["baseline"]["criteria"] if item["applicability"] == "required"]
    validators = [item for item in required if item["evidence_kind"] == "validator"]
    report["required_validator_criterion_ids"] = [item["id"] for item in validators]
    preparation._need(all(item["evidence_kind"] in ("artifact", "validator") for item in required),
                      "unsupported evidence kind remains UNASSESSABLE")
    _artifact_plan(report, document, chain)
    preparation._need(any(item["evidence_kind"] == "artifact" for item in required),
                      "mixed reliability production requires a required artifact criterion")
    return _validator_plan(document, validators)


def _consumer_joins(report: dict[str, Any], document: dict[str, Any],
                    chain: dict[str, Any]) -> dict[str, Any]:
    diagnostic = report["consumer_diagnostic"]
    preparation._need(type(diagnostic) is dict, "the actual reliability receipt consumer is required")
    original = {
        "record_type": preparation.INPUT_TYPE, "version": 1, "root": document["root"],
        "baseline": document["baseline"], "amendments": document["amendments"],
        "candidate": document["candidate"], "bead": document["bead"],
        "validator_evidence": report["validator_evidence"],
    }
    bindings = {**_component_bindings(document, chain), "input_digest": rb.record_digest(original)}
    preparation._need(preparation._canonical(diagnostic["bindings"]) == preparation._canonical(bindings),
                      "validator reliability bindings differ from the complete original context")
    preparation._need(not diagnostic["errors"]
                      and diagnostic["candidate_checks"] == {"before": [], "after": []},
                      "validator reliability consistency checks were refused")
    _original_inventory(diagnostic, chain)
    fields = ("id", "evidence_kind", "applicability")
    expected = [[item[key] for key in fields] for item in chain["baseline"]["criteria"]]
    actual = [[entry[key] for key in fields] for entry in diagnostic["criteria"]]
    preparation._need(preparation._canonical(actual) == preparation._canonical(expected),
                      "validator reliability criterion joins differ from the original inventory")
    preparation._need(preparation._canonical(diagnostic["validator_evidence"])
                      == preparation._canonical(report["validator_evidence"]),
                      "the actual full reliability receipts must remain unchanged")
    return diagnostic


def _validator_subset(report: dict[str, Any], document: dict[str, Any]) -> bool:
    if report["errors"]:
        return False
    chain = rb.resolve_chain(copy.deepcopy(document["baseline"]), copy.deepcopy(document["amendments"]))
    diagnostic = _consumer_joins(report, document, chain)
    required = [item["id"] for item in chain["baseline"]["criteria"]
                if item["applicability"] == "required" and item["evidence_kind"] == "validator"]
    preparation._need(report["required_validator_criterion_ids"] == required,
                      "required validator reliability membership differs from the original baseline")
    preparation._need(sorted(entry["criterion_id"] for entry in report["validator_evidence"]) == sorted(required)
                      and report["checked_command_calls"] == len(required),
                      "all required reliability commands must retain one actual full receipt")
    return all(entry["state"] == "OBSERVED_CONSISTENT"
               for entry in diagnostic["criteria"] if entry["id"] in required)


def _guard(document: dict[str, Any], chain: dict[str, Any], report: dict[str, Any],
           fd: int, identity: tuple[int, ...], phase: str) -> None:
    fresh_chain = rb.resolve_chain(copy.deepcopy(document["baseline"]), copy.deepcopy(document["amendments"]))
    preparation._need(preparation._canonical(fresh_chain) == preparation._canonical(chain),
                      "baseline consistency changed during production")
    checked = ci.check_candidate(copy.deepcopy(document["candidate"]), root=document["root"],
                                 chain=copy.deepcopy(fresh_chain), bead=copy.deepcopy(document["bead"]))
    report["candidate_checks"].append({"phase": phase, "valid": checked["valid"] is True})
    preparation._need(checked["valid"] is True,
                      "candidate consistency check refused: " + "; ".join(checked["errors"][:3]))
    fresh = preparation._directory(document["root"])
    try:
        preparation._need(identity == preparation._identity(fd) == preparation._identity(fresh),
                          "repository root consistency changed during production")
    finally:
        os.close(fresh)


def _wrapper(document: dict[str, Any], chain: dict[str, Any], criterion_id: str, result: Any) -> dict[str, Any]:
    snapshot = preparation._snapshot({"result": result})
    return {
        "record_type": preparation.EVIDENCE_TYPE, "version": 1, "criterion_id": criterion_id,
        "baseline_digest": chain["digest"],
        "candidate_digest": ci.candidate_digest(copy.deepcopy(document["candidate"])),
        "spec": copy.deepcopy(document["commands"][criterion_id]), "result": snapshot["result"],
    }


def _execute(report: dict[str, Any], document: dict[str, Any], chain: dict[str, Any],
             item: tuple[str, dict[str, Any]], guard: Callable[[str], None]) -> bool:
    criterion_id, normalized = item
    guard("before " + criterion_id)
    keep_running = True
    try:
        report["checked_command_calls"] += 1
        result = cc.execute_checked_command(copy.deepcopy(normalized))
        wrapper = _wrapper(document, chain, criterion_id, result)
        report["validator_evidence"].append(wrapper)
        preparation._receipt_shape(wrapper["result"], normalized)
        preparation._snapshot({"validator_evidence": report["validator_evidence"]})
    except Exception as exc:
        _error(report, "checked command production stopped", exc)
        keep_running = False
    try:
        guard("after " + criterion_id)
    except Exception as exc:
        _error(report, "checked command consistency recheck refused", exc)
        keep_running = False
    return keep_running


def _consume(report: dict[str, Any], document: dict[str, Any], guard: Callable[[str], None]) -> None:
    try:
        diagnostic = preparation.prepare(
            document["root"], copy.deepcopy(document["baseline"]), copy.deepcopy(document["candidate"]),
            copy.deepcopy(document["bead"]), copy.deepcopy(report["validator_evidence"]),
            amendments=copy.deepcopy(document["amendments"]))
        report["consumer_diagnostic"] = copy.deepcopy(diagnostic)
    except Exception as exc:
        _error(report, "receipt consumer stopped", exc)
    try:
        guard("after receipt consumer")
    except Exception as exc:
        _error(report, "receipt consumer consistency recheck refused", exc)


def _run(report: dict[str, Any], document: dict[str, Any],
         planner: Callable[..., list[tuple[str, dict[str, Any]]]]) -> None:
    chain = rb.resolve_chain(copy.deepcopy(document["baseline"]), copy.deepcopy(document["amendments"]))
    report["bindings"] = {
        "root": document["root"], "baseline_digest": chain["digest"],
        "candidate_digest": ci.candidate_digest(copy.deepcopy(document["candidate"])),
        "input_digest": rb.record_digest(copy.deepcopy(document)),
        "bead_projection_digest": rb.record_digest(copy.deepcopy(document["bead"])),
    }
    report["required_criterion_ids"] = rb.required_criterion_ids(chain["baseline"])
    with contextlib.ExitStack() as stack:
        fd = preparation._directory(document["root"])
        stack.callback(os.close, fd)
        identity = preparation._identity(fd)

        def guard(phase: str) -> None:
            _guard(document, chain, report, fd, identity, phase)

        try:
            plan = planner(document, chain)
            for item in plan:
                if not _execute(report, document, chain, item, guard):
                    break
        except Exception as exc:
            _error(report, "production refused", exc)
        _consume(report, document, guard)


def _finish(report: dict[str, Any]) -> dict[str, Any]:
    observed = {item["criterion_id"] for item in report["validator_evidence"]}
    report["unobserved_criterion_ids"] = [
        name for name in report["required_criterion_ids"] if name not in observed]
    diagnostic = report["consumer_diagnostic"]
    complete = (not report["errors"] and not report["unobserved_criterion_ids"]
                and diagnostic is not None and diagnostic["observations_complete"] is True)
    report["observations_complete"] = bool(complete)
    if complete:
        report["state"] = "OBSERVED_CONSISTENT"
    elif report["checked_command_calls"]:
        report["state"] = "INCOMPLETE"
    report.update({key: False for key in preparation.AUTHORITY_FIELDS})
    report["report_digest"] = rb.record_digest(copy.deepcopy(report))
    return report


def produce(root: str, initial: Any, candidate: Any, bead: Any, commands: Any, *,
            amendments: list[Any] | tuple[Any, ...] = ()) -> dict[str, Any]:
    """Run independently declared local observations without granting closure authority."""
    report = _report()
    try:
        document = _input(root, initial, candidate, bead, commands, amendments)
        _run(report, document, _plan)
    except Exception as exc:
        _error(report, "production refused", exc)
    return _finish(report)


def _mixed_report() -> dict[str, Any]:
    report = _report()
    report.update(
        record_type="cwo-mixed-evidence-production", production_mode="mixed",
        validator_observations_complete=False, combined_observations_complete=False,
        required_validator_criterion_ids=[], unobserved_validator_criterion_ids=[],
        artifact_diagnostic=None)
    return report


def _finish_mixed(report: dict[str, Any]) -> dict[str, Any]:
    observed = {item["criterion_id"] for item in report["validator_evidence"]}
    report["unobserved_criterion_ids"] = [
        name for name in report["required_criterion_ids"] if name not in observed]
    report["unobserved_validator_criterion_ids"] = [
        name for name in report["required_validator_criterion_ids"] if name not in observed]
    report["observations_complete"] = False
    if report["validator_observations_complete"] and not report["errors"]:
        report["state"] = "VALIDATORS_OBSERVED_CONSISTENT"
    elif report["checked_command_calls"]:
        report["state"] = "INCOMPLETE"
    report.update({key: False for key in preparation.AUTHORITY_FIELDS})
    report["report_digest"] = rb.record_digest(copy.deepcopy(report))
    return report


def produce_mixed(root: str, initial: Any, candidate: Any, bead: Any, commands: Any, *,
                  amendments: list[Any] | tuple[Any, ...] = ()) -> dict[str, Any]:
    """Produce checked reliability receipts while retaining every original artifact obligation."""
    report = _mixed_report()
    try:
        document = _input(root, initial, candidate, bead, commands, amendments)

        def plan(values: dict[str, Any], chain: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
            return _mixed_plan(report, values, chain)

        _run(report, document, plan)
        report["validator_observations_complete"] = _validator_subset(report, document)
    except Exception as exc:
        _error(report, "mixed reliability production refused", exc)
    return _finish_mixed(report)
