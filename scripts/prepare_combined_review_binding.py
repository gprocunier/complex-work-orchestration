#!/usr/bin/env python3
"""Bounded combined review applicability; all reliability authority remains held."""
from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Any

import prepare_final_review_binding as final_review
import prepare_validator_receipts as validators
from cwo_core import candidate_identity as ci
from cwo_core import requirement_baseline as rb

MAX_DOCUMENT = validators.MAX_INPUT
MAX_INPUT = final_review.artifacts.MAX_INPUT
MAX_DEPTH = validators.MAX_DEPTH
MAX_NODES = validators.MAX_NODES
MAX_FINDINGS = 100
INPUT_TYPE = "cwo-combined-observation-input"
CLI_TYPE = "cwo-combined-review-input"
REPORT_TYPE = "cwo-experimental-combined-review-preparation"
REVIEW_TYPE = "cwo-experimental-combined-review"
EXPECTATION_TYPE = "cwo-experimental-combined-review-expectation"
BINDING_TYPE = "cwo-experimental-combined-review-binding"
VERDICTS = ("APPROVE", "REQUEST_CHANGES", "REJECT", "ABSTAIN")
FALSE_FIELDS = (
    "operative", "qualified", "effect_authority", "production_accepted",
    "successful_closure_available", "reviewer_independence_authenticated", "source_authenticated",
    "validator_source_authenticated", "bead_projection_authenticated",
)
OPEN = (
    "protected-custody", "qualified-result-production", "source-authenticity",
    "reviewer-independence-authenticity", "validator-source-authenticity", "bead-projection-authenticity",
    "production-closure", "full-result-evidence", "W06", "#37", "W07", "W23",
    "W05-holds", "W09-holds", "W08-holds", "M1a",
)


class PreparationError(ValueError):
    """An input or observation is outside this bounded reliability contract."""


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise PreparationError(reason)


def _string_size(value: str) -> int:
    _need(len(value) <= MAX_DOCUMENT, "JSON text exceeds the byte limit")
    try:
        size = len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as exc:
        raise PreparationError("input text must be valid UTF-8") from exc
    for char in value:
        if char in '"\\\b\f\n\r\t':
            size += 1
        elif ord(char) < 32:
            size += 5
    return size + 2


def _container(item: dict[str, Any] | list[Any]) -> tuple[list[Any], int]:
    _need(len(item) <= MAX_NODES, "JSON container exceeds the entry limit")
    if type(item) is dict:
        _need(all(type(key) is str for key in item), "JSON object keys must be strings")
        return [part for pair in item.items() for part in pair], 2 + max(0, len(item) - 1) + len(item)
    return item, 2 + max(0, len(item) - 1)


def _scalar_size(item: Any) -> int:
    if type(item) is str:
        return _string_size(item)
    if type(item) is int:
        _need(-(2**63) <= item < 2**63, "JSON integer exceeds the signed 64-bit limit")
        return len(str(item))
    _need(item is None or type(item) is bool, "unsupported native JSON value")
    return 4 if item is None or item is True else 5


def _measure(value: Any) -> None:
    pending, nodes, size = [(value, 0)], 0, 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        _need(depth <= MAX_DEPTH and nodes <= MAX_NODES, "JSON exceeds the depth or node limit")
        if type(item) in (dict, list):
            children, cost = _container(item)
            size += cost
            _need(nodes + len(pending) + len(children) <= MAX_NODES, "JSON exceeds the node limit")
            pending.extend((child, depth + 1) for child in children)
        else:
            size += _scalar_size(item)
        _need(size <= MAX_DOCUMENT, "JSON serialization exceeds the byte limit")


def _encode(value: Any) -> bytes:
    _measure(value)
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")
    _need(len(data) <= MAX_DOCUMENT, "JSON serialization exceeds the byte limit")
    return data


def _decode(data: bytes) -> dict[str, Any]:
    try:
        return validators._decode(data)
    except validators.PreparationError as exc:
        raise PreparationError("JSON parsing or serialization bounds were refused") from exc


def _same(left: Any, right: Any) -> bool:
    return _encode(left) == _encode(right)


def _shape(value: Any, kind: str, fields: tuple[str, ...]) -> None:
    _need(type(value) is dict and set(value) == {"record_type", "version", *fields},
          "record has missing or unsupported fields")
    _record(value, kind)


def _record(value: Any, kind: str) -> None:
    _need(type(value) is dict and value.get("record_type") == kind
          and type(value.get("version")) is int and value["version"] == 1,
          "record type or version is unsupported")


def _context(value: dict[str, Any]) -> None:
    _shape(value, INPUT_TYPE, ("root", "baseline", "amendments", "candidate", "bead", "validator_evidence"))
    root = value["root"]
    _need(type(root) is str and 0 < len(root) <= 4096, "root must be bounded text")
    _need(root.startswith("/") and root == os.path.normpath(root)
          and ".." not in root.split("/") and all(char.isprintable() for char in root),
          "root must be canonical absolute text without control characters")
    for name in ("baseline", "candidate", "bead"):
        _need(type(value[name]) is dict, "baseline, candidate and projection must be objects")
    _need(type(value["amendments"]) is list
          and len(value["amendments"]) <= validators.MAX_AMENDMENTS, "amendments must be a bounded list")
    _need(type(value["validator_evidence"]) is list
          and len(value["validator_evidence"]) <= validators.MAX_EVIDENCE, "validator evidence must be a bounded list")


def _report() -> dict[str, Any]:
    return {
        "record_type": REPORT_TYPE, "version": 1, **dict.fromkeys(FALSE_FIELDS, False),
        "binding_consistent": False, "combined_observations_complete": False,
        "snapshot": None, "binding": None, "review_verdict": None,
        "unresolved_blocking_finding_ids": [], "remaining_open": list(OPEN), "errors": [],
    }


def _finish(result: dict[str, Any]) -> dict[str, Any]:
    result.update(dict.fromkeys(FALSE_FIELDS, False))
    data = _encode(result)
    _need(len(data) + 1 <= MAX_DOCUMENT, "diagnostic exceeds the byte limit")
    return _decode(data)


def _refuse(result: dict[str, Any], reason: str) -> dict[str, Any]:
    result.update(binding_consistent=False, combined_observations_complete=False,
                  snapshot=None, binding=None, errors=[reason])
    return _finish(result)


def _components() -> dict[str, Any]:
    return {
        "artifact": {"module": "prepare_final_review_binding", "api": "observe",
                     "record_type": "cwo-experimental-final-review-preparation", "version": 1},
        "validator": {"module": "prepare_validator_receipts", "api": "prepare",
                      "record_type": "cwo-validator-receipt-observation-preparation", "version": 1},
    }


def _resolved(frozen: bytes) -> bytes:
    data = _decode(frozen)
    _context(data)
    errors = ci.candidate_errors(data["candidate"])
    _need(not errors, "candidate record shape was refused")
    return _encode(rb.resolve_chain(data["baseline"], data["amendments"]))


def _observations(frozen: bytes) -> tuple[bytes, bytes]:
    data = _decode(frozen)
    artifact = _encode(final_review.observe(data["root"], data["baseline"], data["candidate"],
                                            data["bead"], data["amendments"]))
    data = _decode(frozen)
    validator = _encode(validators.prepare(data["root"], data["baseline"], data["candidate"],
                                           data["bead"], data["validator_evidence"], data["amendments"]))
    return artifact, validator


def _prerequisite_bindings(report: dict[str, Any], component: str) -> dict[str, Any]:
    fields = {"resolved_baseline": dict, "candidate": dict, "root": str,
              "bead_projection_digest": str}
    if component == "validator":
        fields["input_digest"] = str
    value = report.get("bindings")
    reason = component + " observation prerequisite bindings are unavailable or malformed"
    _need(type(value) is dict and set(value) == set(fields), reason)
    _need(all(type(value[name]) is expected for name, expected in fields.items()), reason)
    return value


def _bindings(value: dict[str, Any], data: dict[str, Any], chain: dict[str, Any]) -> None:
    _need(_same(value["resolved_baseline"], chain) and _same(value["candidate"], data["candidate"])
          and value["root"] == data["root"], "component baseline, candidate or root differs")
    _need(value["bead_projection_digest"] == rb.record_digest(data["bead"]),
          "component projection binding differs")


def _entries(entries: Any, criteria: list[dict[str, Any]]) -> None:
    _need(type(entries) is list and all(type(entry) is dict for entry in entries),
          "component criterion entries must be objects")
    _need([entry.get("id") for entry in entries] == [item["id"] for item in criteria],
          "component criterion inventory differs")


def _correspondence(frozen: bytes, chain_bytes: bytes, artifact_bytes: bytes, validator_bytes: bytes) -> None:
    data, chain = _decode(frozen), _decode(chain_bytes)
    artifact, validator = _decode(artifact_bytes), _decode(validator_bytes)
    _record(artifact, "cwo-experimental-final-review-preparation")
    _record(validator, "cwo-validator-receipt-observation-preparation")
    snapshot = artifact["snapshot"]
    _need(not artifact["errors"] and type(snapshot) is dict, "artifact observation prerequisites were refused")
    for key, expected in (
        ("root", data["root"]), ("initial_baseline", data["baseline"]), ("amendments", data["amendments"]),
        ("resolved_baseline", chain), ("criterion_inventory", chain["baseline"]["criteria"]),
        ("candidate", data["candidate"]), ("bead_projection", data["bead"]),
        ("candidate_digest", ci.candidate_digest(data["candidate"])),
    ):
        _need(_same(snapshot[key], expected), "artifact snapshot differs from the original context")
    art = snapshot["artifact_report"]
    _record(art, "cwo-artifact-observation-preparation")
    _need(not art["errors"], "artifact observation prerequisites were refused")
    for component, report in (("artifact", art), ("validator", validator)):
        _bindings(_prerequisite_bindings(report, component), data, chain)
        _need(_same(report["candidate_checks"], {"before": [], "after": []}),
              "component candidate consistency checks were refused")
        _need(_same(report["required_criterion_ids"], rb.required_criterion_ids(chain["baseline"])),
              "component required criterion membership differs")
        _entries(report["criteria"], chain["baseline"]["criteria"])
    for entry, criterion in zip(validator["criteria"], chain["baseline"]["criteria"]):
        _need(entry["evidence_kind"] == criterion["evidence_kind"]
              and entry["applicability"] == criterion["applicability"], "validator criterion mapping differs")
    _need(_same(validator["validator_evidence"], data["validator_evidence"]),
          "validator evidence differs from the original context")
    document = {**data, "record_type": validators.INPUT_TYPE}
    _need(validator["bindings"]["input_digest"] == rb.record_digest(document),
          "validator original input binding differs")


def _criteria(chain: dict[str, Any], artifact: dict[str, Any], validator: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    entries = []
    for criterion, art, val in zip(chain["baseline"]["criteria"],
                                    artifact["snapshot"]["artifact_report"]["criteria"], validator["criteria"]):
        kind = criterion["evidence_kind"]
        entry = {"id": criterion["id"], "evidence_kind": kind, "applicability": criterion["applicability"],
                 "state": "UNASSESSABLE", "reason": "required evidence kind is unsupported", "component": None}
        if criterion["applicability"] == "not-applicable":
            entry.update(state="NOT_APPLICABLE", reason=criterion["not_applicable_reason"])
        elif kind == "artifact":
            _need(art["status"] in ("PASSED", "FAILED", "UNASSESSABLE"), "artifact observation state is unsupported")
            entry.update(state=art["status"], reason=art["reason"], component="artifact")
        elif kind == "validator":
            _need(val["state"] in ("OBSERVED_CONSISTENT", "INCONSISTENT", "UNASSESSABLE"),
                  "validator observation state is unsupported")
            entry.update(state=val["state"], reason=val["reason"], component="validator")
        entries.append(entry)
    complete = not validator["errors"] and all(
        entry["state"] in ("PASSED", "OBSERVED_CONSISTENT", "NOT_APPLICABLE") for entry in entries)
    return entries, complete


def _snapshot(frozen: bytes) -> dict[str, Any]:
    chain_bytes = _resolved(frozen)
    artifact_bytes, validator_bytes = _observations(frozen)
    _correspondence(frozen, chain_bytes, artifact_bytes, validator_bytes)
    again_artifact, again_validator = _observations(frozen)
    _need((artifact_bytes, validator_bytes) == (again_artifact, again_validator),
          "component observations changed during the combined consistency check")
    data, chain = _decode(frozen), _decode(chain_bytes)
    check = ci.check_candidate(data["candidate"], root=data["root"], chain=chain, bead=data["bead"])
    _need(check["valid"] is True and check["errors"] == [], "final candidate consistency check was refused")
    data, chain = _decode(frozen), _decode(chain_bytes)
    artifact, validator = _decode(artifact_bytes), _decode(validator_bytes)
    criteria, complete = _criteria(chain, artifact, validator)
    return _decode(_encode({
        "record_type": "cwo-experimental-combined-review-snapshot", "version": 1,
        "input_context": data, "components": _components(), "resolved_baseline": chain,
        "criterion_inventory": chain["baseline"]["criteria"],
        "required_criterion_ids": rb.required_criterion_ids(chain["baseline"]),
        "artifact_observation": artifact, "validator_observation": validator,
        "criteria": criteria, "combined_observations_complete": complete,
    }))


def _text(value: Any, limit: int) -> None:
    _need(type(value) is str and len(value) <= limit and 0 < len(value.strip())
          and all(char.isprintable() for char in value), "review text must be nonempty bounded printable text")


def _review_context(value: Any) -> None:
    _need(type(value) is dict and set(value) == {"review_id", "reviewer", "verdict", "snapshot"},
          "review context has missing or unsupported fields")
    _text(value["review_id"], 64)
    _text(value["reviewer"], 4000)
    _need(type(value["verdict"]) is str and value["verdict"] in VERDICTS, "review verdict is unsupported")
    _need(type(value["snapshot"]) is dict, "review snapshot must be an object")


def _findings(value: Any) -> None:
    _need(type(value) is list and len(value) <= MAX_FINDINGS, "findings must be a bounded list")
    seen = set()
    for finding in value:
        _need(type(finding) is dict and set(finding) == {"id", "blocking", "state", "text"},
              "finding has missing or unsupported fields")
        _text(finding["id"], 64)
        _text(finding["text"], 4000)
        _need(finding["id"].casefold() not in seen, "finding IDs must be unique without regard to case")
        seen.add(finding["id"].casefold())
        _need(type(finding["blocking"]) is bool and type(finding["state"]) is str
              and finding["state"] in ("OPEN", "RESOLVED"), "finding flag or state is unsupported")


def _review(raw: bytes, expected_bytes: bytes) -> dict[str, Any]:
    expected = _decode(expected_bytes)
    _shape(expected, EXPECTATION_TYPE, ("context", "raw_review_sha256"))
    _review_context(expected["context"])
    review = _decode(raw)
    _shape(review, REVIEW_TYPE, ("context", "findings", "summary"))
    _review_context(review["context"])
    _findings(review["findings"])
    _text(review["summary"], 4000)
    _need(_same(review["context"], expected["context"]), "review context differs from the independent expectation")
    _need(type(expected["raw_review_sha256"]) is str
          and expected["raw_review_sha256"] == "sha256:" + hashlib.sha256(raw).hexdigest(),
          "raw review bytes differ from the independent expectation")
    return review


def observe(context: Any) -> dict[str, Any]:
    """Observe both real producers using one private reliability context."""
    result = _report()
    try:
        frozen = _encode(context)
        result["snapshot"] = _snapshot(frozen)
        result["combined_observations_complete"] = result["snapshot"]["combined_observations_complete"]
        return _finish(result)
    except PreparationError as exc:
        return _refuse(result, str(exc))
    except (rb.RequirementBaselineError, ci.CandidateIdentityError):
        return _refuse(result, "baseline, amendment or candidate prerequisites were refused")
    except OSError:
        return _refuse(result, "repository consistency observation was unavailable")


def _frozen_request(context: Any, raw: Any, expected: Any, prepared: Any, checking: bool) -> tuple[bytes, bytes, bytes]:
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_DOCUMENT, "raw review must be bounded immutable bytes")
    inputs = _encode(context)
    expectation = _encode(expected)
    saved = _encode(prepared) if checking else b""
    _need(sum(map(len, (inputs, expectation, saved, raw))) <= MAX_INPUT, "aggregate review input exceeds the byte limit")
    return inputs, expectation, saved


def _run(context: Any, raw: Any, expected: Any, prepared: Any, checking: bool) -> dict[str, Any]:
    result = _report()
    try:
        frozen, expected_bytes, saved = _frozen_request(context, raw, expected, prepared, checking)
        if checking:
            _shape(_decode(saved), REPORT_TYPE, tuple(key for key in result if key not in ("record_type", "version")))
        review = _review(raw, expected_bytes)
        result["review_verdict"] = review["context"]["verdict"]
        result["unresolved_blocking_finding_ids"] = [
            item["id"] for item in review["findings"] if item["blocking"] and item["state"] == "OPEN"]
        snapshot = _snapshot(frozen)
        _need(_same(snapshot, _decode(expected_bytes)["context"]["snapshot"]),
              "review snapshot differs from the complete fresh combined observation")
        result["snapshot"] = snapshot
        result["combined_observations_complete"] = snapshot["combined_observations_complete"]
        if result["review_verdict"] == "APPROVE":
            _need(not result["unresolved_blocking_finding_ids"] and result["combined_observations_complete"],
                  "APPROVE conflicts with unresolved blockers or incomplete required observations")
        result["binding"] = {"record_type": BINDING_TYPE, "version": 1,
                             "expected": _decode(expected_bytes), "raw_review": raw.decode("utf-8", errors="strict")}
        result["binding_consistent"] = True
        result = _finish(result)
        _need(not checking or _encode(result) == saved, "saved diagnostic differs from the current complete binding")
        return result
    except PreparationError as exc:
        return _refuse(result, str(exc))
    except (rb.RequirementBaselineError, ci.CandidateIdentityError):
        return _refuse(result, "baseline, amendment or candidate prerequisites were refused")
    except OSError:
        return _refuse(result, "repository consistency observation was unavailable")


def prepare(context: Any, raw: Any, expected: Any) -> dict[str, Any]:
    """Bind exact raw review bytes to fresh reliability observations without granting authority."""
    return _run(context, raw, expected, None, False)


def consume(prepared: Any, context: Any, raw: Any, expected: Any) -> dict[str, Any]:
    """Recompute reliability observations and compare the complete saved diagnostic."""
    return _run(context, raw, expected, prepared, True)


def _cli(document: dict[str, Any]) -> dict[str, Any]:
    mode = document.get("mode")
    _need(type(mode) is str and mode in ("observe", "prepare", "check"), "CLI mode is unsupported")
    fields = ("mode", "context")
    if mode != "observe":
        fields += ("raw_review", "expected")
    if mode == "check":
        fields += ("prepared",)
    _shape(document, CLI_TYPE, fields)
    if mode == "observe":
        return observe(document["context"])
    _need(type(document["raw_review"]) is str, "CLI raw review must be UTF-8 text")
    raw = document["raw_review"].encode("utf-8", errors="strict")
    if mode == "prepare":
        return prepare(document["context"], raw, document["expected"])
    return consume(document["prepared"], document["context"], raw, document["expected"])


def _cli_diagnostic(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_type": "cwo-combined-review-cli-diagnostic", "version": 1,
        **dict.fromkeys(FALSE_FIELDS, False), "binding_consistent": result["binding_consistent"],
        "combined_observations_complete": result["combined_observations_complete"],
        "snapshot_available": result["snapshot"] is not None, "review_verdict": result["review_verdict"],
        "report_sha256": "sha256:" + hashlib.sha256(_encode(result)).hexdigest(),
        "remaining_open": list(OPEN), "errors": result["errors"],
    }


def main(argv: list[str] | None = None) -> int:
    try:
        args = sys.argv[1:] if argv is None else argv
        _need(type(args) is list and not args, "the CLI accepts one stdin document and no arguments")
        result = _cli(_decode(sys.stdin.buffer.read(MAX_DOCUMENT + 1)))
    except PreparationError as exc:
        result = _refuse(_report(), str(exc))
    except OSError:
        result = _refuse(_report(), "stdin or repository observation was unavailable")
    print(_encode(_cli_diagnostic(result)).decode("utf-8"))
    available = result["binding_consistent"] or result["snapshot"] is not None
    return 0 if available and not result["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
