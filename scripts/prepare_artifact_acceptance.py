#!/usr/bin/env python3
"""Bounded, unwired artifact observations; never acceptance or permission to execute."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from cwo_core import candidate_identity as ci
from cwo_core import requirement_baseline as rb
from cwo_core import typed_artifact_requirement as typed_requirement

MAX_DOCUMENT = 4 * 1024 * 1024
MAX_INPUT = 16 * 1024 * 1024
MAX_ARTIFACT = 1024 * 1024
MAX_TOTAL_ARTIFACT = 8 * 1024 * 1024
MAX_DEPTH = 32
MAX_NODES = 100_000
MAX_AMENDMENTS = 32
PREFIX = "cwo-artifact-v1:"
HEX = re.compile(r"[0-9a-f]{64}")


class PreparationError(ValueError):
    """Input or observation exceeds this preparation tool's supported corpus."""


def _decode(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_DOCUMENT:
        raise PreparationError("JSON document exceeds the byte limit")
    text = data.decode("utf-8", errors="strict")
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise PreparationError("JSON exceeds the depth limit")
        elif char in "]}":
            depth -= 1

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PreparationError("duplicate JSON key")
            result[key] = value
        return result

    def integer(text: str) -> int:
        if len(text.lstrip("-")) > 19 or not -(2**63) <= int(text) < 2**63:
            raise PreparationError("JSON integer is outside the signed 64-bit bound")
        return int(text)

    def no_number(text: str) -> Any:
        raise PreparationError("floating point and nonfinite JSON numbers are unsupported")

    value = json.loads(text, object_pairs_hook=unique, parse_int=integer,
                       parse_float=no_number, parse_constant=no_number)
    _bounded(value)
    if type(value) is not dict:
        raise PreparationError("a JSON document must be an object")
    return value


def _bounded_children(item: Any, depth: int) -> list[tuple[Any, int]]:
    if type(item) is dict:
        if any(type(key) is not str for key in item):
            raise PreparationError("JSON object keys must be strings")
        return [(part, depth + 1) for pair in item.items() for part in pair]
    return [(part, depth + 1) for part in item]


def _scalar_size(item: Any) -> int:
    if type(item) is str:
        return len(item.encode("utf-8", errors="strict"))
    if type(item) is int:
        if not -(2**63) <= item < 2**63:
            raise PreparationError("JSON integer is outside the signed 64-bit bound")
    elif item is not None and type(item) is not bool:
        raise PreparationError("unsupported JSON value type")
    return 0


def _bounded(value: Any) -> None:
    pending, nodes, size = [(value, 0)], 0, 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > MAX_DEPTH or nodes > MAX_NODES or (type(item) in (dict, list) and len(item) > MAX_NODES):
            raise PreparationError("JSON exceeds the depth or node limit")
        if type(item) in (dict, list):
            pending.extend(_bounded_children(item, depth))
        else:
            size += _scalar_size(item)
        if size > MAX_DOCUMENT:
            raise PreparationError("JSON strings exceed the byte limit")


def _snapshot(value: Any) -> dict[str, Any]:
    _bounded(value)
    return _decode(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"))


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory(root: str | Path) -> int:
    path = os.fspath(root)
    if not os.path.isabs(path) or ".." in path.split("/"):
        raise PreparationError("an explicit absolute root without '..' is required")
    with contextlib.ExitStack() as stack:
        current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, current)
        for part in path.split("/"):
            if part in ("", "."):
                continue
            current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            stack.callback(os.close, current)
        return os.dup(current)


def _read_regular(fd: int, limit: int) -> bytes:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise PreparationError("not a regular file")
    if before.st_size > limit:
        raise PreparationError("regular file exceeds the byte limit")
    data = bytearray()
    while len(data) <= limit:
        chunk = os.read(fd, min(65536, limit + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    if len(data) > limit or _identity(before) != _identity(os.fstat(fd)):
        raise PreparationError("regular file exceeded its bound or changed while read")
    return bytes(data)


def _document(path: str) -> bytes:
    absolute = os.path.abspath(path)
    with contextlib.ExitStack() as stack:
        parent = _directory(os.path.dirname(absolute))
        stack.callback(os.close, parent)
        fd = os.open(os.path.basename(absolute), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        stack.callback(os.close, fd)
        return _read_regular(fd, MAX_DOCUMENT)


def _path(value: Any) -> str:
    if type(value) is not str or not value or len(value) > 4096:
        raise PreparationError("predicate path must be bounded text")
    parts = value.split("/")
    if (len(parts) > 128 or any(part in ("", ".", "..") or part.casefold() == ".git" for part in parts)
            or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value)):
        raise PreparationError("predicate path must be canonical, relative and outside .git")
    return value


def _within(path: str, scope: str) -> bool:
    return scope == "." or path == scope or path.startswith(scope + "/")


def _predicate(criterion: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    typed_requirement.check_evidence_kind(criterion["requirement"], criterion["evidence_kind"])
    text = criterion["expected_outcome"]
    if criterion["evidence_kind"] != "artifact" or not text.startswith(PREFIX):
        raise PreparationError("UNASSESSABLE: requires an explicit supported artifact predicate")
    predicate = _decode(text[len(PREFIX):].encode("utf-8"))
    op = predicate.get("op")
    fields = {"op", "path", "sha256"} if op == "regular-file-sha256" else {"op", "path"}
    if op not in ("regular-file-sha256", "path-absent") or set(predicate) != fields:
        raise PreparationError("UNASSESSABLE: unsupported predicate or fields")
    path = _path(predicate["path"])
    if not any(_within(path, scope) for scope in candidate["delivery_scope"]["paths"]):
        raise PreparationError("observed path is outside candidate delivery scope")
    if any(_within(path, excluded) for excluded in candidate["excluded_paths"]):
        raise PreparationError("observed path is excluded from the candidate")
    if op == "regular-file-sha256":
        if type(predicate["sha256"]) is not str or not HEX.fullmatch(predicate["sha256"]):
            raise PreparationError("predicate sha256 must be 64 lowercase hex digits")
    typed_requirement.check_artifact_expectation(criterion["requirement"], predicate)
    return predicate


def _artifact(root_fd: int, path: str, limit: int, read_bytes: bool) -> dict[str, Any]:
    """One observer read per distinct path; existing candidate checks also read working content."""
    with contextlib.ExitStack() as stack:
        current = root_fd
        walked: list[tuple[int, str, os.stat_result]] = []
        try:
            for part in path.split("/")[:-1]:
                try:
                    info = os.stat(part, dir_fd=current, follow_symlinks=False)
                except FileNotFoundError:
                    return {"type": "absent"}
                if not stat.S_ISDIR(info.st_mode):
                    raise PreparationError("artifact ancestor is a symlink or is not a directory")
                fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                stack.callback(os.close, fd)
                if _identity(info) != _identity(os.fstat(fd)):
                    raise PreparationError("artifact ancestor changed while opened")
                walked.append((current, part, info))
                current = fd
            name = path.rsplit("/", 1)[-1]
            try:
                info = os.stat(name, dir_fd=current, follow_symlinks=False)
            except FileNotFoundError:
                return {"type": "absent"}
            if stat.S_ISDIR(info.st_mode) and not read_bytes:
                return {"type": "directory"}
            if not stat.S_ISREG(info.st_mode):
                raise PreparationError("artifact is a symlink, special file or unexpected directory")
            if not read_bytes:
                return {"type": "file"}
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)
            stack.callback(os.close, fd)
            if _identity(info) != _identity(os.fstat(fd)):
                raise PreparationError("artifact changed while opened")
            data = _read_regular(fd, limit)
            if _identity(info) != _identity(os.stat(name, dir_fd=current, follow_symlinks=False)):
                raise PreparationError("artifact pathname changed while read")
            return {"type": "file", "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                    "mode": f"{stat.S_IMODE(info.st_mode):o}"}
        finally:
            for parent, name, info in walked:
                try:
                    unchanged = _identity(info) == _identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                except OSError as exc:
                    raise PreparationError("artifact ancestor disappeared during observation") from exc
                if not unchanged:
                    raise PreparationError("artifact ancestor changed during observation")


def _report() -> dict[str, Any]:
    return {
        "record_type": "cwo-artifact-observation-preparation", "version": 1,
        "artifact_observations_complete": False, "qualified": False, "effect_authority": False,
        "successful_closure_available": False, "production_accepted": False,
        "bead_projection_authenticated": False,
        "remaining_open": ["final-review", "qualified-validator", "protected-custody", "production-closure",
                           "W06", "#37", "M1a"],
        "bindings": {}, "required_criterion_ids": [], "criteria": [], "errors": [],
        "candidate_checks": {"before": [], "after": []},
    }


def _finish(report: dict[str, Any]) -> dict[str, Any]:
    report["report_digest"] = rb.record_digest(report)
    return report


def _preparation_inputs(root: str | Path, initial: Any, candidate: Any, bead: Any,
                        amendments: list[Any] | tuple[Any, ...]) -> tuple[str, list[dict[str, Any]]]:
    root = os.fspath(root)
    if type(root) is not str:
        raise PreparationError("root must be text")
    root.encode("utf-8", errors="strict")
    if len(amendments) > MAX_AMENDMENTS:
        raise PreparationError("too many amendments")
    values = [_snapshot(value) for value in (initial, candidate, bead, *amendments)]
    if sum(len(json.dumps(value, ensure_ascii=False).encode("utf-8")) for value in values) > MAX_INPUT:
        raise PreparationError("aggregate input exceeds the byte limit")
    return root, values


def _baseline_chain(initial: dict[str, Any], changes: list[dict[str, Any]]) -> dict[str, Any]:
    errors = rb.baseline_errors(initial)
    if errors:
        raise rb.RequirementBaselineError(errors)
    return rb.resolve_chain(initial, changes)


def _report_bindings(root: str, chain: dict[str, Any], candidate: dict[str, Any],
                     bead: dict[str, Any]) -> dict[str, Any]:
    return {"resolved_baseline": chain, "candidate": candidate,
            "bead_projection_digest": rb.record_digest(bead), "root": os.fspath(root)}


def _criterion_entry(criterion: dict[str, Any]) -> dict[str, Any]:
    applicable = criterion["applicability"] == "required"
    return {
        "id": criterion["id"], "status": "UNASSESSABLE" if applicable else "NOT_APPLICABLE",
        "reason": "prerequisites unavailable" if applicable else criterion["not_applicable_reason"],
    }


def _prepare_predicates(criteria: list[dict[str, Any]], entries: list[dict[str, Any]],
                        candidate: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    predicates: dict[str, dict[str, Any]] = {}
    entries = [dict(entry) for entry in entries]
    for criterion, entry in zip(criteria, entries):
        if criterion["applicability"] != "required":
            continue
        try:
            predicates[criterion["id"]] = _predicate(criterion, candidate)
        except (ValueError, UnicodeError) as exc:
            entry["reason"] = str(exc)
    return predicates, entries


def _observe_artifacts(
    root_fd: int, predicates: dict[str, dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    observations: dict[str, dict[str, Any]] = {}
    observation_errors: dict[str, str] = {}
    budget = MAX_TOTAL_ARTIFACT
    for path in sorted({item["path"] for item in predicates.values()}):
        needs_bytes = any(item["path"] == path and item["op"] == "regular-file-sha256"
                          for item in predicates.values())
        limit = min(MAX_ARTIFACT, budget)
        budget -= limit
        try:
            observed = _artifact(root_fd, path, limit, needs_bytes)
            budget += limit - observed.get("size", 0)
            observations[path] = observed
        except (OSError, ValueError) as exc:
            observation_errors[path] = str(exc)
    return observations, observation_errors


def _binding_probe_errors(
    root: str, chain: dict[str, Any], candidate: dict[str, Any],
    predicates: dict[str, dict[str, Any]], observations: dict[str, dict[str, Any]],
) -> dict[str, str]:
    probe_paths = sorted({item["path"] for item in predicates.values()
                          if item["op"] == "regular-file-sha256"
                          and observations.get(item["path"], {}).get("type") == "file"})
    if not probe_paths:
        return {}
    try:
        probe_scope = sorted(set(candidate["delivery_scope"]["paths"] + probe_paths))
        probe = ci.capture_candidate(root, chain=chain, base_commit=candidate["base_commit"],
                                     scope_paths=probe_scope, excluded_paths=candidate["excluded_paths"])
        expected = {**candidate, "delivery_scope": {"paths": probe_scope, "live_resources": []}}
        if ci.candidate_digest(probe) != ci.candidate_digest(expected):
            raise PreparationError("candidate drift during artifact binding probe")
    except (OSError, ValueError) as exc:
        return {path: "artifact is not bound to the current candidate: " + str(exc) for path in probe_paths}
    return {}


def _bound_deletions(root: str, candidate: dict[str, Any],
                     predicates: dict[str, dict[str, Any]]) -> set[str]:
    deleted = {item["path"] for item in candidate["worktree_manifest"] if item["change"] == "deleted"}
    absent = {item["path"] for item in predicates.values() if item["op"] == "path-absent"}
    if not absent - deleted:
        return deleted
    raw = ci._capture(Path(root))
    if (raw["head_commit"], raw["head"]) != (candidate["commit"], candidate["tree"]):
        raise PreparationError("candidate drift during committed deletion observation")
    budget = ci.workspace_capture.Budget.start(**ci.HISTORY_LIMITS)
    try:
        store = ci.workspace_capture.object_store(raw["dirs"][1], raw["object_format"], budget)
        try:
            base = store.tree_manifest(store.peel_to_tree(candidate["base_commit"]),
                                       budget.take_entry, budget.take_bytes)
            current = store.tree_manifest(candidate["tree"], budget.take_entry, budget.take_bytes)
            return deleted | (set(base) - set(current))
        finally:
            store.close()
    except (ci.git_store.StoreError, ci.workspace_capture.BudgetExhausted) as exc:
        raise PreparationError("committed deletions cannot be observed completely") from exc


def _unbound_absence(predicate: dict[str, Any], observed: dict[str, Any],
                     deleted: set[str]) -> bool:
    return (predicate["op"] == "path-absent" and observed["type"] == "absent"
            and predicate["path"] not in deleted)


def _assessed_entry(
    entry: dict[str, Any], predicates: dict[str, dict[str, Any]], deleted: set[str],
    observations: dict[str, dict[str, Any]], observation_errors: dict[str, str],
) -> dict[str, Any]:
    entry = dict(entry)
    predicate = predicates.get(entry["id"])
    if predicate is None:
        return entry
    path = predicate["path"]
    entry["predicate"] = predicate
    if path in observation_errors:
        entry["reason"] = observation_errors[path]
        return entry
    observed = observations[path]
    entry["observation"] = observed
    if _unbound_absence(predicate, observed, deleted):
        entry["reason"] = "absence is supported only for a candidate-bound tracked deletion"
        return entry
    passed = (observed["type"] == "absent" if predicate["op"] == "path-absent" else
              observed.get("sha256") == predicate["sha256"] and observed["type"] == "file")
    entry["status"] = "PASSED" if passed else "FAILED"
    entry["reason"] = "artifact predicate matched" if passed else "artifact predicate did not match"
    return entry


def prepare(root: str | Path, initial: Any, candidate: Any, bead: Any,
            amendments: list[Any] | tuple[Any, ...] = ()) -> dict[str, Any]:
    """Diagnostic only. Caller projections and self-hashes provide no authenticated authority."""
    report = _report()
    try:
        root, values = _preparation_inputs(root, initial, candidate, bead, amendments)
        initial, candidate, bead, *changes = values
        chain = _baseline_chain(initial, changes)
        report["bindings"] = _report_bindings(root, chain, candidate, bead)
        report["required_criterion_ids"] = rb.required_criterion_ids(chain["baseline"])
        report["criteria"] = [_criterion_entry(criterion) for criterion in chain["baseline"]["criteria"]]
        with contextlib.ExitStack() as stack:
            root_fd = _directory(root)
            stack.callback(os.close, root_fd)
            root_identity = _identity(os.fstat(root_fd))
            before = ci.check_candidate(candidate, root=root, chain=chain, bead=bead)
            report["candidate_checks"]["before"] = before["errors"]
            if not before["valid"]:
                report["errors"].append("current candidate/baseline/projection prerequisites failed")
                return _finish(report)
            predicates, report["criteria"] = _prepare_predicates(
                chain["baseline"]["criteria"], report["criteria"], candidate)
            observations, observation_errors = _observe_artifacts(root_fd, predicates)
            observation_errors.update(_binding_probe_errors(root, chain, candidate, predicates, observations))
            deleted = _bound_deletions(root, candidate, predicates)
            report["criteria"] = [
                _assessed_entry(entry, predicates, deleted, observations, observation_errors)
                for entry in report["criteria"]
            ]
            after = ci.check_candidate(candidate, root=root, chain=chain, bead=bead)
            report["candidate_checks"]["after"] = after["errors"]
            fresh_fd = _directory(root)
            stack.callback(os.close, fresh_fd)
            if root_identity != _identity(os.fstat(fresh_fd)) or root_identity != _identity(os.fstat(root_fd)):
                raise PreparationError("root changed during observations")
            report["artifact_observations_complete"] = (
                after["valid"] and not report["errors"]
                and all(entry["status"] in ("PASSED", "NOT_APPLICABLE") for entry in report["criteria"])
            )
    except (rb.RequirementBaselineError, ci.CandidateIdentityError) as exc:
        report["errors"].extend(exc.errors)
    except (OSError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        report["errors"].append(f"preparation refused: {type(exc).__name__}: {exc}")
    return _finish(report)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise PreparationError(message)


def main(argv: list[str] | None = None) -> int:
    try:
        parser = _Parser(description="Prepare diagnostic artifact observations; successful closure stays unavailable.")
        parser.add_argument("--root", required=True, help="Explicit absolute repository root.")
        parser.add_argument("--baseline", required=True)
        parser.add_argument("--amendment", action="append", default=[])
        parser.add_argument("--candidate", required=True)
        parser.add_argument("--bead-json", required=True, help="Caller fixture projection, never a live journal.")
        args = parser.parse_args(argv)
        if len(args.amendment) > MAX_AMENDMENTS:
            raise PreparationError("too many amendments")
        documents, total = [], 0
        for path in (args.baseline, args.candidate, args.bead_json, *args.amendment):
            data = _document(path)
            total += len(data)
            if total > MAX_INPUT:
                raise PreparationError("aggregate input exceeds the byte limit")
            documents.append(_decode(data))
        initial, candidate, bead, *amendments = documents
        report = prepare(args.root, initial, candidate, bead, amendments)
    except (OSError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        report = _report()
        report["errors"].append(f"preparation refused: {type(exc).__name__}: {exc}")
        report = _finish(report)
    print(json.dumps(report, sort_keys=True, ensure_ascii=True, allow_nan=False))
    return 0 if report["artifact_observations_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
