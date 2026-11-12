"""Requirement baselines and their amendments (issue #37).

A requirement baseline records, before implementation, what a Bead must deliver: one entry per criterion with a
stable ID, the authoritative requirement and its reference, the expected observable outcome, whether the criterion
applies and the kind of evidence it needs. It holds obligations only. It has no place for results, and nothing in
this module builds a baseline from results; it only checks one that was recorded.

The digest is SHA-256 over a deterministic serialization of the whole record. A Bead retains its baseline by a
comment whose text is exactly the reference line for that record. An amendment names the prior digest and carries
the complete next baseline; the criteria it declares as added, removed and changed must be exactly the difference.
In this version only amendments that add criteria are supported. Removing or changing a recorded criterion would
remove or weaken an obligation, which needs authority that CWO cannot verify yet, so those amendments are refused.

These checks are read-only: they open no files, run no commands and never write to Beads. Successful closure stays
unavailable (see scripts/close_bead_with_summary.py); this module is one of the parts it will need.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

BASELINE_RECORD_TYPE = "cwo-requirement-baseline"
AMENDMENT_RECORD_TYPE = "cwo-requirement-amendment"
RECORD_VERSION = 1
BASELINE_FIELDS = ("record_type", "version", "bead_id", "baseline_version", "criteria")
CRITERION_FIELDS = ("id", "requirement", "reference", "expected_outcome", "applicability", "evidence_kind")
NOT_APPLICABLE_REASON = "not_applicable_reason"
AMENDMENT_FIELDS = (
    "record_type",
    "version",
    "bead_id",
    "amendment_id",
    "prior_digest",
    "prior_baseline_version",
    "added_criterion_ids",
    "removed_criterion_ids",
    "changed_criterion_ids",
    "rationale",
    "authority",
    "baseline",
)
AUTHORITY_FIELDS = ("role", "reference")
APPLICABILITY = ("required", "not-applicable")
# The evidence types a run readiness plan already maps criteria to.
EVIDENCE_KINDS = ("artifact", "validator", "review-gate")
# Keys that would record an outcome rather than an obligation. The record is closed, so any of them is refused
# anyway; naming them gives a clearer refusal.
RESULT_KEYS = frozenset({
    "status", "result", "results", "observed", "observation", "outcome", "passed", "failed", "evidence",
    "evidence_digest", "evidence_refs", "producer", "candidate", "verdict", "score",
})
_ID = re.compile(r"[A-Za-z][A-Za-z0-9]*(?:[._-][A-Za-z0-9]+)*")
_BEAD_ID = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_CONTROL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
MAX_ID = 64
MAX_TEXT = 4000
MAX_CRITERIA = 500
REFERENCE_PREFIX = "cwo-requirement-baseline"
_REFERENCE = re.compile(
    r"cwo-requirement-baseline bead=(?P<bead>\S+) version=(?P<version>[1-9][0-9]*) digest=(?P<digest>sha256:[0-9a-f]{64})"
)


class RequirementBaselineError(ValueError):
    """A baseline, amendment or Bead reference that cannot be used, with every reason found."""

    def __init__(self, errors: Sequence[str]) -> None:
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def record_digest(record: Mapping[str, Any]) -> str:
    """``sha256:`` and the hex SHA-256 of the record's deterministic serialization."""
    return "sha256:" + hashlib.sha256(_canonical(dict(record))).hexdigest()


def load_record(text: str) -> dict[str, Any]:
    """Parse one JSON record, refusing duplicate keys (which would make the digest ambiguous)."""

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        keys = [key for key, _ in pairs]
        duplicates = sorted({key for key in keys if keys.count(key) > 1})
        if duplicates:
            raise RequirementBaselineError([f"duplicate key(s) {', '.join(duplicates)}"])
        return dict(pairs)

    try:
        value = json.loads(text, object_pairs_hook=unique)
    except RequirementBaselineError:
        raise
    except ValueError as exc:
        raise RequirementBaselineError([f"not JSON: {exc}"]) from exc
    if type(value) is not dict:
        raise RequirementBaselineError(["a record must be a JSON object"])
    return value


def _is_int(value: Any) -> bool:
    return type(value) is int


def _text_errors(value: Any, where: str) -> list[str]:
    if type(value) is not str or not value.strip():
        return [f"{where} must be non-empty text"]
    if len(value) > MAX_TEXT:
        return [f"{where} is longer than {MAX_TEXT} characters"]
    if _CONTROL.search(value):
        return [f"{where} cannot contain control or text-direction characters"]
    return []


def _closed(value: Mapping[str, Any], allowed: Sequence[str], where: str) -> list[str]:
    extra = sorted(set(value) - set(allowed))
    if not extra:
        return []
    results = [key for key in extra if key in RESULT_KEYS]
    errors = []
    if results:
        errors.append(
            f"{where} carries result field(s) {', '.join(results)}: a baseline records obligations, not results"
        )
    others = [key for key in extra if key not in RESULT_KEYS]
    if others:
        errors.append(f"{where} has unsupported field(s) {', '.join(others)}")
    return errors


def baseline_errors(record: Any) -> list[str]:
    """Every reason ``record`` is not a usable version 1 requirement baseline; empty when it is."""
    if type(record) is not dict:
        return ["a requirement baseline must be a JSON object"]
    if record.get("record_type") != BASELINE_RECORD_TYPE:
        return [f"record_type must be {BASELINE_RECORD_TYPE}"]
    if record.get("version") != RECORD_VERSION or not _is_int(record.get("version")):
        return [f"unsupported requirement baseline version {record.get('version')!r}; only {RECORD_VERSION} is supported"]
    errors = _closed(record, BASELINE_FIELDS, "the baseline")
    errors += [f"the baseline is missing {field}" for field in BASELINE_FIELDS if field not in record]
    bead = record.get("bead_id")
    if type(bead) is not str or not _BEAD_ID.fullmatch(bead):
        errors.append("bead_id must be a Bead ID (letters, digits, '.', '_' and '-')")
    if not _is_int(record.get("baseline_version")) or record["baseline_version"] < 1:
        errors.append("baseline_version must be an integer of at least 1")
    criteria = record.get("criteria")
    if type(criteria) is not list or not criteria:
        return errors + ["criteria must be a non-empty list"]
    if len(criteria) > MAX_CRITERIA:
        return errors + [f"criteria has more than {MAX_CRITERIA} entries"]
    seen: dict[str, str] = {}
    required = 0
    for index, criterion in enumerate(criteria):
        where = f"criteria[{index}]"
        if type(criterion) is not dict:
            errors.append(f"{where} must be an object")
            continue
        allowed = (*CRITERION_FIELDS, NOT_APPLICABLE_REASON)
        errors += _closed(criterion, allowed, where)
        errors += [f"{where} is missing {field}" for field in CRITERION_FIELDS if field not in criterion]
        criterion_id = criterion.get("id")
        if type(criterion_id) is not str or len(criterion_id) > MAX_ID or not _ID.fullmatch(criterion_id):
            errors.append(f"{where}.id must be a stable ID: a letter, then letters and digits, optionally joined "
                          f"by single '.', '_' or '-', at most {MAX_ID} characters")
        else:
            folded = criterion_id.casefold()
            if folded in seen:
                errors.append(f"{where}.id {criterion_id!r} repeats {seen[folded]!r}")
            seen.setdefault(folded, criterion_id)
            where = f"criterion {criterion_id}"
        for field in ("requirement", "reference", "expected_outcome"):
            if field in criterion:
                errors += _text_errors(criterion[field], f"{where} {field}")
        applicability = criterion.get("applicability")
        if applicability not in APPLICABILITY:
            errors.append(f"{where} applicability must be one of: {', '.join(APPLICABILITY)}")
        elif applicability == "required":
            required += 1
            if NOT_APPLICABLE_REASON in criterion:
                errors.append(f"{where} is required, so it cannot carry {NOT_APPLICABLE_REASON}")
        elif NOT_APPLICABLE_REASON not in criterion:
            errors.append(f"{where} is not-applicable, so it needs {NOT_APPLICABLE_REASON}")
        else:
            errors += _text_errors(criterion[NOT_APPLICABLE_REASON], f"{where} {NOT_APPLICABLE_REASON}")
        if criterion.get("evidence_kind") not in EVIDENCE_KINDS:
            errors.append(f"{where} evidence_kind must be one of: {', '.join(EVIDENCE_KINDS)}")
    if not required and type(criteria) is list:
        errors.append("the baseline has no required criterion")
    return errors


def criteria_by_id(record: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """The criteria of a valid baseline, keyed by ID."""
    return {criterion["id"]: dict(criterion) for criterion in record["criteria"]}


def required_criterion_ids(record: Mapping[str, Any]) -> list[str]:
    """IDs of the criteria a valid baseline marks as required, in recorded order."""
    return [criterion["id"] for criterion in record["criteria"] if criterion["applicability"] == "required"]


def _id_list_errors(value: Any, where: str) -> list[str]:
    if type(value) is not list or any(type(item) is not str for item in value):
        return [f"{where} must be a list of criterion IDs"]
    if len(set(value)) != len(value):
        return [f"{where} repeats an ID"]
    return []


def amendment_errors(prior: Mapping[str, Any], amendment: Any) -> list[str]:
    """Every reason ``amendment`` cannot be applied to the valid baseline ``prior``; empty when it can.

    Only amendments that add criteria are supported. An amendment that removes or changes a criterion is refused
    even when every other field is consistent, because CWO cannot yet verify the authority that removing or
    weakening a recorded obligation needs, and it cannot tell a clarification from a weakening.
    """
    if type(amendment) is not dict:
        return ["an amendment must be a JSON object"]
    if amendment.get("record_type") != AMENDMENT_RECORD_TYPE:
        return [f"record_type must be {AMENDMENT_RECORD_TYPE}"]
    if amendment.get("version") != RECORD_VERSION or not _is_int(amendment.get("version")):
        return [f"unsupported amendment version {amendment.get('version')!r}; only {RECORD_VERSION} is supported"]
    errors = _closed(amendment, AMENDMENT_FIELDS, "the amendment")
    errors += [f"the amendment is missing {field}" for field in AMENDMENT_FIELDS if field not in amendment]
    if errors:
        return errors
    name = amendment["amendment_id"]
    if type(name) is not str or len(name) > MAX_ID or not _ID.fullmatch(name):
        return ["amendment_id must be a stable ID"]
    where = f"amendment {name}"
    prior_digest = record_digest(prior)
    if amendment["bead_id"] != prior["bead_id"]:
        errors.append(f"{where} is for Bead {amendment['bead_id']!r}, not {prior['bead_id']!r}")
    if amendment["prior_digest"] != prior_digest:
        errors.append(f"{where} amends {amendment['prior_digest']!r}, not the current baseline {prior_digest}")
    if amendment["prior_baseline_version"] != prior["baseline_version"] or not _is_int(amendment["prior_baseline_version"]):
        errors.append(f"{where} amends baseline version {amendment['prior_baseline_version']!r}, not {prior['baseline_version']}")
    errors += _text_errors(amendment["rationale"], f"{where} rationale")
    authority = amendment["authority"]
    if type(authority) is not dict:
        errors.append(f"{where} authority must be an object with role and reference")
    else:
        errors += _closed(authority, AUTHORITY_FIELDS, f"{where} authority")
        for field in AUTHORITY_FIELDS:
            errors += _text_errors(authority.get(field), f"{where} authority {field}")
    declared = {}
    for field in ("added_criterion_ids", "removed_criterion_ids", "changed_criterion_ids"):
        field_errors = _id_list_errors(amendment[field], f"{where} {field}")
        errors += field_errors
        declared[field] = set(amendment[field]) if not field_errors else None
    new = amendment["baseline"]
    new_errors = baseline_errors(new)
    errors += [f"{where} baseline: {error}" for error in new_errors]
    if errors:
        return errors
    if new["bead_id"] != prior["bead_id"]:
        errors.append(f"{where} baseline is for Bead {new['bead_id']!r}, not {prior['bead_id']!r}")
    if new["baseline_version"] != prior["baseline_version"] + 1:
        errors.append(f"{where} baseline version must be {prior['baseline_version'] + 1}, not {new['baseline_version']}")
    before, after = criteria_by_id(prior), criteria_by_id(new)
    actual = {
        "added_criterion_ids": set(after) - set(before),
        "removed_criterion_ids": set(before) - set(after),
        "changed_criterion_ids": {key for key in set(before) & set(after) if before[key] != after[key]},
    }
    for field, ids in actual.items():
        if declared[field] != ids:
            errors.append(
                f"{where} declares {field} {sorted(declared[field])} but the baselines differ by {sorted(ids)}; "
                "an amendment must name exactly what it changes"
            )
    if not any(actual.values()):
        errors.append(f"{where} changes no criterion")
    weakened = sorted(actual["removed_criterion_ids"] | actual["changed_criterion_ids"])
    if weakened:
        errors.append(
            f"{where} removes or changes criteria {', '.join(weakened)}: removing or weakening a recorded "
            "obligation needs authority that CWO cannot verify yet, and a change cannot be told apart from a "
            f"weakening, so only amendments that add criteria are supported; the baseline stays at {prior_digest}"
        )
    return errors


def resolve_chain(initial: Any, amendments: Sequence[Any] = ()) -> dict[str, Any]:
    """The effective baseline after applying ``amendments`` in order, or RequirementBaselineError.

    Returns ``bead_id``, ``baseline`` (the effective record), ``digest``, ``version``, ``amendment_ids`` and
    ``baselines``: one entry per version with its ``version`` and ``digest``, oldest first.
    """
    errors = baseline_errors(initial)
    if errors:
        raise RequirementBaselineError(["initial baseline: " + error for error in errors])
    current = initial
    if current["baseline_version"] != 1:
        raise RequirementBaselineError([
            f"initial baseline: baseline_version is {current['baseline_version']}; a chain starts at version 1"
        ])
    versions = [{"version": 1, "digest": record_digest(current)}]
    names: list[str] = []
    for index, amendment in enumerate(amendments):
        errors = amendment_errors(current, amendment)
        if not errors and amendment["amendment_id"] in names:
            errors = [f"amendment {amendment['amendment_id']} appears twice"]
        if errors:
            raise RequirementBaselineError([f"amendments[{index}]: {error}" for error in errors])
        names.append(amendment["amendment_id"])
        current = amendment["baseline"]
        versions.append({"version": current["baseline_version"], "digest": record_digest(current)})
    return {
        "bead_id": current["bead_id"],
        "baseline": current,
        "digest": versions[-1]["digest"],
        "version": current["baseline_version"],
        "amendment_ids": names,
        "baselines": versions,
    }


def reference_line(bead_id: str, version: int, digest: str) -> str:
    """The exact comment text by which a Bead retains one baseline version."""
    return f"{REFERENCE_PREFIX} bead={bead_id} version={version} digest={digest}"


def scan_reference_comments(
    comments: Sequence[Any], prefix: str, pattern: re.Pattern[str], label: str
) -> tuple[list[tuple[int, re.Match[str]]], list[str]]:
    """Find the reference comments in a Bead's comment list and refuse anything else that looks like one.

    A reference is a comment whose whole text, apart from surrounding whitespace, matches ``pattern``. Every other
    comment is inspected line by line: a line that starts with ``prefix`` (in any letter case), or that contains
    text matching ``pattern`` anywhere, is refused, because a malformed or embedded reference could otherwise record
    a conflicting baseline or candidate that the check never sees. Prose that merely mentions the prefix is not a
    reference and is ignored. Returns the references found, as (comment index, match), and one error per refused
    comment.
    """
    folded = prefix.casefold()
    anywhere = re.compile(pattern.pattern, re.IGNORECASE)
    found: list[tuple[int, re.Match[str]]] = []
    errors: list[str] = []
    for index, comment in enumerate(comments):
        text = comment.get("text") if type(comment) is dict else None
        if type(text) is not str:
            continue
        match = pattern.fullmatch(text.strip())
        if match:
            found.append((index, match))
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.casefold().startswith(folded):
                errors.append(f"comment {index} starts like a {label} but is not one: {stripped[:120]!r}")
                break
            if anywhere.search(line):
                errors.append(
                    f"comment {index} contains a {label} inside other text but is not one: a reference must be the "
                    f"whole comment ({stripped[:120]!r})"
                )
                break
    return found, errors


def bead_reference_errors(bead: Any, chain: Mapping[str, Any]) -> list[str]:
    """Every reason the Bead projection ``bead`` (``bd show --json`` with comments) does not retain ``chain``.

    Each baseline version in the chain must be recorded by a comment that is exactly its reference line, in version
    order. Any other baseline reference on the Bead (a different digest, version, or Bead) means the baseline was
    replaced or diverged without an amendment in the chain, and is refused. So is a comment with a line that starts
    like a baseline reference, or that carries one inside other text (see ``scan_reference_comments``). This reads
    the projection only.
    """
    if type(bead) is not dict:
        return ["the Bead projection must be an object"]
    if bead.get("id") != chain["bead_id"]:
        return [f"the Bead projection is {bead.get('id')!r}, not {chain['bead_id']!r}"]
    comments = bead.get("comments")
    if type(comments) is not list:
        return [f"the Bead projection for {chain['bead_id']} has no comment list"]
    expected = {
        reference_line(chain["bead_id"], entry["version"], entry["digest"]): entry["version"] for entry in chain["baselines"]
    }
    first_seen: dict[int, int] = {}
    found, errors = scan_reference_comments(comments, REFERENCE_PREFIX, _REFERENCE, "baseline reference")
    for index, match in found:
        line = match.group(0)
        if line in expected:
            first_seen.setdefault(expected[line], index)
        else:
            errors.append(
                f"comment {index} records baseline {match['digest']} (version {match['version']}, Bead "
                f"{match['bead']}), which is not in this chain: the baseline was replaced or diverged without an "
                "amendment"
            )
    for entry in chain["baselines"]:
        if entry["version"] not in first_seen:
            errors.append(
                f"baseline version {entry['version']} ({entry['digest']}) is not recorded on {chain['bead_id']}"
            )
    order = [first_seen[entry["version"]] for entry in chain["baselines"] if entry["version"] in first_seen]
    if order != sorted(order):
        errors.append(f"the baseline references on {chain['bead_id']} are not in version order")
    return errors
