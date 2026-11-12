#!/usr/bin/env python3
"""Experimental final-review identity and freshness; never approval or effect authority."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any

import prepare_artifact_acceptance as artifacts
from cwo_core import candidate_identity as ci

MAX_REVIEW = artifacts.MAX_DOCUMENT
MAX_FINDINGS = 100
FALSE_FIELDS = (
    "qualified", "effect_authority", "successful_closure_available", "production_accepted",
    "reviewer_independence_authenticated", "source_authenticated",
)
REMAINING_OPEN = [
    "final-review-authenticity", "qualified-validator", "protected-custody", "production-closure",
    "full-result-evidence", "W06", "#37", "W07", "M1a",
]
VERDICTS = ("APPROVE", "REQUEST_CHANGES", "REJECT", "ABSTAIN")
REFUSALS = (OSError, ValueError, TypeError, OverflowError, RecursionError)


def _report() -> dict[str, Any]:
    return {
        "record_type": "cwo-experimental-final-review-preparation", "version": 1,
        **dict.fromkeys(FALSE_FIELDS, False),
        "binding_consistent": False, "artifact_observations_complete": False,
        "snapshot": None, "binding": None, "review_verdict": None,
        "unresolved_blocking_finding_ids": [], "remaining_open": list(REMAINING_OPEN),
        "errors": [],
    }


def _freeze(value: Any) -> bytes:
    """Bound before serialization; retain only private canonical bytes across readers."""
    return json.dumps(artifacts._snapshot(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _finish(result: dict[str, Any]) -> dict[str, Any]:
    data = _freeze(result)
    if len(data) + 1 > artifacts.MAX_DOCUMENT:
        raise artifacts.PreparationError("diagnostic exceeds the byte limit")
    return artifacts._decode(data)


def _refuse(result: dict[str, Any], exc: Exception) -> dict[str, Any]:
    result.update(binding_consistent=False, artifact_observations_complete=False, snapshot=None, binding=None)
    message = str(exc).encode("utf-8", errors="replace").decode("utf-8")[:240]
    result["errors"] = [f"final-review preparation refused: {type(exc).__name__}: {message}"]
    return _finish(result)


def _closed(value: Any, fields: tuple[str, ...], label: str) -> None:
    if type(value) is not dict or set(value) != set(fields):
        raise artifacts.PreparationError(f"{label} has missing or unsupported fields")


def _shape(value: Any, kind: str, fields: tuple[str, ...], label: str) -> None:
    _closed(value, ("record_type", "version", *fields), label)
    if value["record_type"] != kind or type(value["version"]) is not int or value["version"] != 1:
        raise artifacts.PreparationError(f"{label} has an unsupported record type or version")


def _text(value: Any, label: str) -> None:
    if type(value) is not str or not value.strip() or len(value) > 4000:
        raise artifacts.PreparationError(f"{label} must be nonempty bounded text")
    if any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value):
        raise artifacts.PreparationError(f"{label} contains unsupported control characters")


def _context(value: Any) -> None:
    _closed(value, ("review_id", "reviewer", "verdict", "snapshot"), "review context")
    _text(value["review_id"], "review ID")
    _text(value["reviewer"], "declared reviewer")
    if len(value["review_id"]) > 64 or value["verdict"] not in VERDICTS:
        raise artifacts.PreparationError("review ID or verdict is unsupported")
    if type(value["snapshot"]) is not dict:
        raise artifacts.PreparationError("review snapshot must be an object")


def _inputs(root: str, initial: Any, candidate: Any, bead: Any, amendments: Any) -> bytes:
    if type(root) is not str or not root.startswith("/") or len(root) > 4096:
        raise artifacts.PreparationError("root must be explicit bounded absolute text")
    if ".." in root.split("/"):
        raise artifacts.PreparationError("root cannot contain a parent component")
    if type(amendments) not in (list, tuple) or len(amendments) > artifacts.MAX_AMENDMENTS:
        raise artifacts.PreparationError("amendments must be a bounded ordered list or tuple")
    return _freeze({"root": root, "initial": initial, "candidate": candidate,
                    "bead": bead, "amendments": list(amendments)})


def _observe(frozen: bytes) -> bytes:
    data = artifacts._decode(frozen)
    report = artifacts._decode(_freeze(artifacts.prepare(
        data["root"], data["initial"], data["candidate"], data["bead"], data["amendments"])))
    if report["errors"] or report["candidate_checks"] != {"before": [], "after": []}:
        raise artifacts.PreparationError("artifact or current candidate prerequisites are unavailable")
    data = artifacts._decode(frozen)
    chain = report["bindings"]["resolved_baseline"]
    for criterion, entry in zip(chain["baseline"]["criteria"], report["criteria"]):
        if criterion["applicability"] != "required":
            continue
        try:
            artifacts._predicate(criterion, data["candidate"])
        except (ValueError, UnicodeError):
            continue
        if entry["status"] == "UNASSESSABLE":
            raise artifacts.PreparationError("a supported artifact observation is unavailable")
    return _freeze({
        "root": data["root"], "initial_baseline": data["initial"],
        "amendments": data["amendments"], "resolved_baseline": chain,
        "criterion_inventory": chain["baseline"]["criteria"],
        "candidate": data["candidate"], "candidate_digest": ci.candidate_digest(data["candidate"]),
        "bead_projection": data["bead"], "artifact_report": report,
    })


def _findings(value: Any) -> None:
    if type(value) is not list or len(value) > MAX_FINDINGS:
        raise artifacts.PreparationError("findings must be a bounded list")
    seen: set[str] = set()
    for finding in value:
        _closed(finding, ("id", "blocking", "state", "text"), "finding")
        _text(finding["id"], "finding ID")
        _text(finding["text"], "finding text")
        name = finding["id"].casefold()
        if len(finding["id"]) > 64 or name in seen:
            raise artifacts.PreparationError("finding IDs must be bounded and unique")
        seen.add(name)
        if type(finding["blocking"]) is not bool or finding["state"] not in ("OPEN", "RESOLVED"):
            raise artifacts.PreparationError("finding blocking flag or state is unsupported")


def _review(raw: Any, expected: dict[str, Any]) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_REVIEW:
        raise artifacts.PreparationError("raw review must be nonempty bounded immutable bytes")
    _shape(expected, "cwo-experimental-final-review-expectation",
           ("context", "raw_review_sha256"), "expected review context")
    _context(expected["context"])
    review = artifacts._decode(raw)
    _shape(review, "cwo-experimental-final-review", ("context", "findings", "summary"), "review observation")
    _context(review["context"])
    _findings(review["findings"])
    _text(review["summary"], "review summary")
    if _freeze(review["context"]) != _freeze(expected["context"]):
        raise artifacts.PreparationError("review context differs from the independent expectation")
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if type(expected["raw_review_sha256"]) is not str or expected["raw_review_sha256"] != digest:
        raise artifacts.PreparationError("raw review bytes differ from the independent expectation")
    return review


def observe(root: str, initial: Any, candidate: Any, bead: Any,
            amendments: list[Any] | tuple[Any, ...] = ()) -> dict[str, Any]:
    """Observe a bounded snapshot for review preparation, without authenticating its source."""
    result = _report()
    try:
        snapshot = artifacts._decode(_observe(_inputs(root, initial, candidate, bead, amendments)))
        result["snapshot"] = snapshot
        result["artifact_observations_complete"] = snapshot["artifact_report"]["artifact_observations_complete"]
        return _finish(result)
    except REFUSALS as exc:
        return _refuse(result, exc)


def _binding_inputs(root: str, initial: Any, candidate: Any, bead: Any,
                    raw: Any, expected: Any, amendments: Any, prepared: Any,
                    checking: bool) -> tuple[bytes, bytes, bytes, dict[str, Any]]:
    """Freeze bounded inputs before review parsing or artifact observation."""
    inputs = _inputs(root, initial, candidate, bead, amendments)
    expected_bytes = _freeze(expected)
    saved = _freeze(prepared) if checking else b""
    if type(raw) is not bytes or len(raw) > MAX_REVIEW:
        raise artifacts.PreparationError("raw review must be bounded immutable bytes")
    if len(inputs) + len(expected_bytes) + len(saved) + len(raw) > artifacts.MAX_INPUT:
        raise artifacts.PreparationError("aggregate input exceeds the byte limit")
    expected = artifacts._decode(expected_bytes)
    if checking:
        _shape(artifacts._decode(saved), "cwo-experimental-final-review-preparation",
               tuple(key for key in _report() if key not in ("record_type", "version")), "prepared diagnostic")
    return inputs, expected_bytes, saved, expected


def _run(root: str, initial: Any, candidate: Any, bead: Any,
         raw: Any, expected: Any, amendments: Any, prepared: Any, checking: bool) -> dict[str, Any]:
    result = _report()
    try:
        inputs, expected_bytes, saved, expected = _binding_inputs(
            root, initial, candidate, bead, raw, expected, amendments, prepared, checking)
        review = _review(raw, expected)
        result["review_verdict"] = review["context"]["verdict"]
        result["unresolved_blocking_finding_ids"] = [
            item["id"] for item in review["findings"] if item["blocking"] and item["state"] == "OPEN"]
        if result["review_verdict"] == "APPROVE" and result["unresolved_blocking_finding_ids"]:
            raise artifacts.PreparationError("APPROVE conflicts with unresolved blocking findings")
        snapshot = _observe(inputs)
        if _freeze(expected["context"]["snapshot"]) != snapshot:
            raise artifacts.PreparationError("review snapshot is stale or belongs to a different context")
        result["artifact_observations_complete"] = (
            artifacts._decode(snapshot)["artifact_report"]["artifact_observations_complete"])
        result["binding"] = {
            "record_type": "cwo-experimental-final-review-binding", "version": 1,
            "expected": artifacts._decode(expected_bytes), "raw_review": raw.decode("utf-8", errors="strict"),
        }
        result["binding_consistent"] = True
        result = _finish(result)
        if checking and _freeze(result) != saved:
            raise artifacts.PreparationError("prepared diagnostic differs from the current complete binding")
        return result
    except REFUSALS as exc:
        return _refuse(result, exc)


def prepare(root: str, initial: Any, candidate: Any, bead: Any, raw: Any, expected: Any,
            amendments: list[Any] | tuple[Any, ...] = ()) -> dict[str, Any]:
    """Prepare exact review applicability; declared approval supplies no authority."""
    return _run(root, initial, candidate, bead, raw, expected, amendments, None, False)


def consume(prepared: Any, root: str, initial: Any, candidate: Any, bead: Any,
            raw: Any, expected: Any, amendments: list[Any] | tuple[Any, ...] = ()) -> dict[str, Any]:
    """Reobserve current applicability and compare the whole saved diagnostic."""
    return _run(root, initial, candidate, bead, raw, expected, amendments, prepared, True)


def _arguments(argv: list[str]) -> argparse.Namespace:
    if len(argv) > 100 or any(type(item) is not str for item in argv):
        raise artifacts.PreparationError("arguments must be a bounded text list")
    if sum(len(item.encode("utf-8", errors="strict")) for item in argv) > 65536:
        raise artifacts.PreparationError("arguments exceed the byte limit")
    parser = artifacts._Parser(add_help=False, allow_abbrev=False)
    parser.add_argument("mode", choices=("observe", "prepare", "check"))
    for name in ("root", "baseline", "candidate", "bead-json"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--amendment", action="append", default=[])
    for name in ("review", "expected-context", "prepared"):
        parser.add_argument("--" + name)
    args = parser.parse_args(argv)
    if len(args.amendment) > artifacts.MAX_AMENDMENTS:
        raise artifacts.PreparationError("too many amendments")
    present = (args.review is not None, args.expected_context is not None, args.prepared is not None)
    if present != {"observe": (False, False, False), "prepare": (True, True, False), "check": (True, True, True)}[args.mode]:
        raise artifacts.PreparationError("review input options do not match the selected mode")
    return args


def _cli(args: argparse.Namespace) -> dict[str, Any]:
    paths = [("initial", args.baseline), ("candidate", args.candidate), ("bead", args.bead_json)]
    paths.extend(("amendment", path) for path in args.amendment)
    for key, path in (("raw", args.review), ("expected", args.expected_context), ("prepared", args.prepared)):
        if path is not None:
            paths.append((key, path))
    values: dict[str, Any] = {"amendments": []}
    total = 0
    for key, path in paths:
        data = artifacts._document(path)
        total += len(data)
        if total > artifacts.MAX_INPUT:
            raise artifacts.PreparationError("aggregate input exceeds the byte limit")
        value = data if key == "raw" else artifacts._decode(data)
        if key == "amendment":
            values["amendments"].append(value)
        else:
            values[key] = value
    common = (args.root, values["initial"], values["candidate"], values["bead"])
    if args.mode == "observe":
        return observe(*common, amendments=values["amendments"])
    if args.mode == "prepare":
        return prepare(*common, values["raw"], values["expected"], values["amendments"])
    return consume(values["prepared"], *common, values["raw"], values["expected"], values["amendments"])


def main(argv: list[str] | None = None) -> int:
    try:
        args = _arguments(sys.argv[1:] if argv is None else argv)
        result = _cli(args)
    except REFUSALS as exc:
        result = _refuse(_report(), exc)
    print(_freeze(result).decode("utf-8"))
    available = result["binding_consistent"] or result["snapshot"] is not None
    return 0 if available and not result["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
