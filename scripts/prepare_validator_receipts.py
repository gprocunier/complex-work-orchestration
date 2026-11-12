#!/usr/bin/env python3
"""Read-only validator receipt consistency; successful closure stays unavailable."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import os
import re
import sys
from typing import Any

from cwo_core import candidate_identity as ci
from cwo_core import checked_command as cc
from cwo_core import requirement_baseline as rb
from cwo_core import typed_artifact_requirement as typed_requirement

MAX_INPUT = 4 * 1024 * 1024
MAX_DEPTH = 32
MAX_NODES = 100_000
MAX_AMENDMENTS = 32
MAX_EVIDENCE = 500
PREFIX = "cwo-checked-validator-v1:"
INPUT_TYPE = "cwo-validator-receipt-preparation-input"
EVIDENCE_TYPE = "cwo-validator-evidence"
HEX = re.compile(r"[0-9a-f]{64}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
AUTHORITY_FIELDS = (
    "operative", "qualified", "effect_authority", "production_accepted",
    "successful_closure_available", "validator_source_authenticated", "bead_projection_authenticated",
)
INPUT_FIELDS = {
    "record_type", "version", "root", "baseline", "amendments", "candidate", "bead", "validator_evidence",
}
RESULT_FIELDS = {
    "result_type", "version", "command_id", "spec_sha256", "mode", "complexity",
    "preflight_status", "linter", "execution_status", "exit_code", "linted_sha256", "executed_sha256",
    "hash_match", "execution_started", "mutation_started", "mutated_paths", "failure_class",
    "quarantine_required", "diagnostics", "quoting_error_prevented", "avoided_retry_cycles",
}


class PreparationError(ValueError):
    """An input or observation is outside the supported consistency contract."""


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise PreparationError(reason)


def _shape(value: Any, fields: set[str], reason: str) -> None:
    _need(type(value) is dict, reason)
    _need(set(value) == fields, reason)


def _string_end(text: str, start: int) -> int:
    escaped = False
    for index in range(start + 1, len(text)):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            return index + 1
    raise PreparationError("JSON string is incomplete")


def _scalar_end(text: str, start: int) -> int:
    while start < len(text) and text[start] not in ' \t\r\n,:[]{}"':
        start += 1
    return start


def _scan(text: str) -> None:
    depth, nodes, cursor = 0, 0, 0
    while cursor < len(text):
        char = text[cursor]
        if char in " \t\r\n,:":
            cursor += 1
            continue
        nodes += 1
        _need(nodes <= MAX_NODES, "JSON exceeds the token limit")
        if char == '"':
            cursor = _string_end(text, cursor)
            continue
        if char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
        else:
            cursor = _scalar_end(text, cursor) - 1
        _need(0 <= depth <= MAX_DEPTH, "JSON exceeds the depth limit or has unmatched containers")
        cursor += 1


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _need(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _integer(text: str) -> int:
    _need(len(text.lstrip("-")) <= 19, "JSON integer exceeds the signed 64-bit bound")
    value = int(text)
    _need(-(2**63) <= value < 2**63, "JSON integer exceeds the signed 64-bit bound")
    return value


def _no_number(text: str) -> Any:
    raise PreparationError("floating point and nonfinite JSON numbers are unsupported")


def _scalar_size(value: Any) -> int:
    if type(value) is str:
        return len(value.encode("utf-8", errors="strict"))
    if type(value) is int:
        _need(-(2**63) <= value < 2**63, "input integer exceeds the signed 64-bit bound")
    else:
        _need(value is None or type(value) is bool, "unsupported input value type")
    return 0


def _bounded(value: Any) -> None:
    pending, nodes, size = [(value, 0)], 0, 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        _need(depth <= MAX_DEPTH and nodes <= MAX_NODES, "input exceeds the depth or node limit")
        if type(item) in (dict, list):
            _need(len(item) <= MAX_NODES, "input container exceeds the node limit")
            children = list(item)
            if type(item) is dict:
                _need(all(type(key) is str for key in item), "input object keys must be strings")
                children += list(item.values())
            pending.extend((child, depth + 1) for child in children)
        else:
            size += _scalar_size(item)
        _need(size <= MAX_INPUT, "input strings exceed the byte limit")


def _decode(data: bytes) -> dict[str, Any]:
    try:
        _need(type(data) is bytes and len(data) <= MAX_INPUT, "JSON exceeds the byte limit")
        text = data.decode("utf-8", errors="strict")
        _scan(text)
        value = json.loads(text, object_pairs_hook=_unique, parse_int=_integer,
                           parse_float=_no_number, parse_constant=_no_number)
        _bounded(value)
        _need(type(value) is dict, "the input document must be an object")
        return value
    except PreparationError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise PreparationError("JSON is malformed or contains unsupported text or numbers") from exc


def _snapshot(value: Any) -> dict[str, Any]:
    try:
        _bounded(value)
        data = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8", errors="strict")
        return _decode(data)
    except UnicodeError as exc:
        raise PreparationError("input text must be valid UTF-8") from exc


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _root_text(root: Any) -> None:
    _need(type(root) is str and 0 < len(root) <= 4096, "root must be bounded text")
    _need(root.startswith("/") and root == os.path.normpath(root), "root must be canonical and absolute")
    _need(".." not in root.split("/") and not any(ord(char) < 32 for char in root), "root contains unsupported text")


def _document(value: dict[str, Any]) -> None:
    _shape(value, INPUT_FIELDS, "input document must contain exactly the supported fields")
    _need(value["record_type"] == INPUT_TYPE, "unsupported input record type")
    _need(type(value["version"]) is int and value["version"] == 1, "unsupported input version")
    _root_text(value["root"])
    _need(type(value["amendments"]) is list, "amendments must be a list")
    _need(len(value["amendments"]) <= MAX_AMENDMENTS, "too many amendments")
    _need(type(value["validator_evidence"]) is list, "validator evidence must be a list")
    _need(len(value["validator_evidence"]) <= MAX_EVIDENCE, "too many validator evidence wrappers")
    _need(type(value["bead"]) is dict, "the Bead projection must be an object")


def _directory(root: str) -> int:
    with contextlib.ExitStack() as stack:
        current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, current)
        for part in root.split("/"):
            if not part:
                continue
            current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            stack.callback(os.close, current)
        return os.dup(current)


def _identity(fd: int) -> tuple[int, ...]:
    info = os.fstat(fd)
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _contract(criterion: dict[str, Any]) -> dict[str, Any]:
    try:
        typed_requirement.check_evidence_kind(criterion["requirement"], criterion["evidence_kind"])
    except ValueError as exc:
        raise PreparationError(str(exc)) from exc
    _need(criterion["evidence_kind"] == "validator", "unsupported evidence kind remains UNASSESSABLE")
    text = criterion["expected_outcome"]
    _need(text.startswith(PREFIX), "an independently predeclared validator contract is required")
    contract = _decode(text[len(PREFIX):].encode("utf-8"))
    _shape(contract, {"command_id", "spec_sha256", "stdout_sha256"}, "unsupported validator contract fields")
    command_id = contract["command_id"]
    _need(type(command_id) is str and 0 < len(command_id) <= 128, "expected command ID must be bounded text")
    _need(all(32 <= ord(char) < 127 for char in command_id), "expected command ID must use printable ASCII")
    for field in ("spec_sha256", "stdout_sha256"):
        _need(type(contract[field]) is str and HEX.fullmatch(contract[field]) is not None,
              "expected hashes must be 64 lowercase hex digits")
    return contract


def _index(evidence: list[Any], ids: set[str]) -> dict[str, dict[str, Any]]:
    index, receipts = {}, set()
    fields = {"record_type", "version", "criterion_id", "baseline_digest", "candidate_digest", "spec", "result"}
    for wrapper in evidence:
        _shape(wrapper, fields, "validator evidence must contain exactly the supported fields")
        _need(wrapper["record_type"] == EVIDENCE_TYPE, "unsupported validator evidence type")
        _need(type(wrapper["version"]) is int and wrapper["version"] == 1, "unsupported validator evidence version")
        criterion_id = wrapper["criterion_id"]
        _need(type(criterion_id) is str, "evidence criterion ID must be text")
        _need(criterion_id in ids and criterion_id not in index, "unknown or duplicate evidence criterion ID")
        for field in ("baseline_digest", "candidate_digest"):
            _need(type(wrapper[field]) is str and DIGEST.fullmatch(wrapper[field]) is not None,
                  "evidence context needs lowercase baseline and candidate digests")
        _need(type(wrapper["spec"]) is dict and type(wrapper["result"]) is dict, "evidence needs a spec and full result")
        result = wrapper["result"]
        receipt_key = _canonical([result.get("command_id"), result.get("spec_sha256")])
        _need(receipt_key not in receipts, "a command receipt is mapped more than once")
        receipts.add(receipt_key)
        index[criterion_id] = wrapper
    return index


def _normalized(spec: dict[str, Any], root: str) -> dict[str, Any]:
    _need(spec.get("cwd") == root, "specification cwd must equal the explicit root before normalization")
    _need(type(spec.get("version")) is int, "specification version must be an integer")
    _need(spec.get("mutation_intent") == "none" and spec.get("allowed_paths") == [], "only read-only specs are supported")
    try:
        normalized = cc.normalize_command_spec(copy.deepcopy(spec))
    except ValueError as exc:
        raise PreparationError("checked-command specification refused: " + str(exc)) from exc
    _need(normalized["cwd"] == root, "normalized specification cwd differs from the explicit root")
    return normalized


def _receipt_shape(result: dict[str, Any], normalized: dict[str, Any]) -> None:
    _shape(result, RESULT_FIELDS, "receipt must retain the full existing result shape")
    _shape(result["diagnostics"], {"stdout", "stderr"}, "receipt diagnostics must contain stdout and stderr")
    for value in result["diagnostics"].values():
        _need(type(value) is str and len(value) <= 4096, "receipt diagnostics must retain bounded producer text")
    expected = cc.classify_command_complexity(copy.deepcopy(normalized))
    _need(_canonical(result["complexity"]) == _canonical(expected), "receipt complexity differs from producer semantics")


def _receipt_success(result: dict[str, Any]) -> None:
    expected = {
        "preflight_status": "passed", "execution_status": "passed", "execution_started": True,
        "exit_code": 0, "hash_match": True, "quarantine_required": False, "failure_class": None,
        "mutation_started": False, "mutated_paths": [], "quoting_error_prevented": False,
        "avoided_retry_cycles": 0,
    }
    _need(type(result["exit_code"]) is int, "receipt exit code must be an integer, never a boolean")
    _need(all(_canonical(result[key]) == _canonical(value) for key, value in expected.items()),
          "receipt must record strict success without failure, quarantine or mutation")


def _receipt_source(result: dict[str, Any], normalized: dict[str, Any]) -> None:
    expected = [None, None, None]
    if normalized["mode"] != "argv":
        digest = _sha(normalized["source"].encode("utf-8"))
        linter = {"python-source": "py_compile", "shell-source": "bash -n"}[normalized["mode"]]
        expected = [digest, digest, linter]
    actual = [result["linted_sha256"], result["executed_sha256"], result["linter"]]
    _need(_canonical(actual) == _canonical(expected), "receipt source hashes or linter differ from exact source bytes")


def _consume(wrapper: dict[str, Any], contract: dict[str, Any], root: str,
             baseline_digest: str, candidate_digest: str) -> dict[str, Any]:
    _need(wrapper["baseline_digest"] == baseline_digest, "evidence baseline differs from the independently resolved baseline")
    _need(wrapper["candidate_digest"] == candidate_digest, "evidence candidate differs from the supplied candidate")
    normalized = _normalized(wrapper["spec"], root)
    digest = _sha(_canonical(normalized))
    _need(normalized["command_id"] == contract["command_id"], "command differs from the independently expected command")
    _need(digest == contract["spec_sha256"], "specification differs from the independently expected specification")
    result = wrapper["result"]
    _receipt_shape(result, normalized)
    expected = {"result_type": cc.RESULT_TYPE, "version": cc.VERSION,
                "command_id": normalized["command_id"], "spec_sha256": digest, "mode": normalized["mode"]}
    _need(type(result["version"]) is int, "receipt version must be an integer")
    _need(_canonical({key: result[key] for key in expected}) == _canonical(expected),
          "receipt type, version, command, specification or mode differs")
    _receipt_success(result)
    _receipt_source(result, normalized)
    stdout_digest = _sha(result["diagnostics"]["stdout"].encode("utf-8"))
    _need(stdout_digest == contract["stdout_sha256"], "diagnostic stdout differs from independently expected bytes")
    return {"normalized_spec_sha256": digest, "stdout_sha256": stdout_digest}


def _entry(criterion: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": criterion["id"], "evidence_kind": criterion["evidence_kind"],
        "applicability": criterion["applicability"], "state": "UNASSESSABLE",
        "reason": criterion.get("not_applicable_reason", "required evidence has not been observed"),
    }


def _assess(entry: dict[str, Any], criterion: dict[str, Any], index: dict[str, dict[str, Any]],
            document: dict[str, Any], chain: dict[str, Any]) -> None:
    if criterion["applicability"] != "required":
        return
    try:
        contract = _contract(criterion)
    except PreparationError as exc:
        entry["reason"] = str(exc)
        return
    entry["expected_contract"] = contract
    wrapper = index.get(criterion["id"])
    if wrapper is None:
        entry["reason"] = "required validator evidence is missing"
        return
    try:
        entry["observation"] = _consume(wrapper, contract, document["root"], chain["digest"],
                                       ci.candidate_digest(copy.deepcopy(document["candidate"])))
        entry.update(state="OBSERVED_CONSISTENT", reason="receipt matches the independently supplied contract")
    except PreparationError as exc:
        entry.update(state="INCONSISTENT", reason=str(exc))


def _observe(report: dict[str, Any], document: dict[str, Any], chain: dict[str, Any]) -> None:
    criteria = chain["baseline"]["criteria"]
    index = _index(document["validator_evidence"], {criterion["id"] for criterion in criteria})
    for entry, criterion in zip(report["criteria"], criteria):
        _assess(entry, criterion, index, document, chain)


def _check(document: dict[str, Any], chain: dict[str, Any]) -> dict[str, Any]:
    return ci.check_candidate(copy.deepcopy(document["candidate"]), root=document["root"],
                              chain=copy.deepcopy(chain), bead=copy.deepcopy(document["bead"]))


def _invalidate(report: dict[str, Any]) -> None:
    for entry in report["criteria"]:
        if entry["state"] == "OBSERVED_CONSISTENT":
            entry.update(state="INCONSISTENT", reason="current observation context failed its consistency recheck")


def _run(report: dict[str, Any], document: dict[str, Any]) -> None:
    chain = rb.resolve_chain(copy.deepcopy(document["baseline"]), copy.deepcopy(document["amendments"]))
    report["bindings"] = {"root": document["root"], "resolved_baseline": copy.deepcopy(chain),
                          "candidate": copy.deepcopy(document["candidate"]),
                          "bead_projection_digest": rb.record_digest(copy.deepcopy(document["bead"])),
                          "input_digest": rb.record_digest(copy.deepcopy(document))}
    report["validator_evidence"] = copy.deepcopy(document["validator_evidence"])
    report["required_criterion_ids"] = rb.required_criterion_ids(chain["baseline"])
    report["criteria"] = [_entry(criterion) for criterion in chain["baseline"]["criteria"]]
    with contextlib.ExitStack() as stack:
        fd = _directory(document["root"])
        stack.callback(os.close, fd)
        identity = _identity(fd)
        before = _check(document, chain)
        report["candidate_checks"]["before"] = before["errors"]
        if before["valid"] is True:
            try:
                _observe(report, document, chain)
            except PreparationError as exc:
                report["errors"].append(str(exc))
        else:
            report["errors"].append("current candidate, baseline or projection prerequisites failed")
        after = _check(document, chain)
        report["candidate_checks"]["after"] = after["errors"]
        if after["valid"] is not True:
            report["errors"].append("current candidate, baseline or projection changed or was refused")
        fresh = _directory(document["root"])
        stack.callback(os.close, fresh)
        if identity != _identity(fd) or identity != _identity(fresh):
            report["errors"].append("repository root changed during observation")
        if report["errors"]:
            _invalidate(report)


def _report() -> dict[str, Any]:
    return {
        "record_type": "cwo-validator-receipt-observation-preparation", "version": 1,
        "state": "UNASSESSABLE", "observations_complete": False,
        **{key: False for key in AUTHORITY_FIELDS},
        "bindings": {}, "required_criterion_ids": [], "criteria": [], "validator_evidence": [], "errors": [],
        "candidate_checks": {"before": [], "after": []},
        "remaining_open": ["final-review", "qualified-validator", "protected-custody", "production-closure",
                           "W06", "#37", "M1a", "W05-holds", "W09-holds"],
        "limitations": [
            "Caller context and hashes do not authenticate producer custody or the Bead projection.",
            "Current candidate checks are best effort reads without an atomic lock or authenticated time order.",
            "A receipt does not prove that its command tested the whole candidate.",
            "Existing candidate capture may create and remove private scratch files.",
            "Artifact, prose, service and review obligations remain unassessable in this consumer.",
        ],
    }


def _finish(report: dict[str, Any]) -> dict[str, Any]:
    required = [entry for entry in report["criteria"] if entry["applicability"] == "required"]
    states = {entry["state"] for entry in required}
    if report["errors"] or "INCONSISTENT" in states:
        report["state"] = "INCONSISTENT"
    elif required and states == {"OBSERVED_CONSISTENT"}:
        report["state"] = "OBSERVED_CONSISTENT"
    report["observations_complete"] = report["state"] == "OBSERVED_CONSISTENT"
    report.update({key: False for key in AUTHORITY_FIELDS})
    report["report_digest"] = rb.record_digest(copy.deepcopy(report))
    return report


def prepare_document(value: Any) -> dict[str, Any]:
    """Observe a private input snapshot without granting execution or closure authority."""
    report = _report()
    try:
        document = _snapshot(value)
        _document(document)
        _run(report, document)
    except (rb.RequirementBaselineError, ci.CandidateIdentityError) as exc:
        report["errors"].extend(exc.errors)
        _invalidate(report)
    except (PreparationError, OSError) as exc:
        report["errors"].append("preparation refused: " + str(exc))
        _invalidate(report)
    return _finish(report)


def prepare(root: str, initial: Any, candidate: Any, bead: Any, validator_evidence: Any,
            amendments: list[Any] | tuple[Any, ...] = ()) -> dict[str, Any]:
    """Consume supplied records only; candidate capture keeps its existing private scratch behavior."""
    changes = list(amendments) if type(amendments) in (list, tuple) else amendments
    return prepare_document({
        "record_type": INPUT_TYPE, "version": 1, "root": root, "baseline": initial,
        "amendments": changes, "candidate": candidate, "bead": bead, "validator_evidence": validator_evidence,
    })


def main(argv: list[str] | None = None) -> int:
    try:
        _need(not (sys.argv[1:] if argv is None else argv), "the CLI accepts one stdin document and no arguments")
        value = _decode(sys.stdin.buffer.read(MAX_INPUT + 1))
        report = prepare_document(value)
    except (PreparationError, OSError) as exc:
        report = _report()
        report["errors"].append("preparation refused: " + str(exc))
        report = _finish(report)
    print(json.dumps(report, sort_keys=True, ensure_ascii=True, allow_nan=False))
    return 0 if report["observations_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
