"""Exact, caller-approved Git transition matching for retrospective captures.

Records are assertions supplied by a trusted caller, not authenticated grants.
Nothing in captured repository data supplies approval or changes capture rules.
"""
from __future__ import annotations

import json
from typing import Any


BINDING_FIELDS = (
    "capture_identity", "git_executable", "object_format", "head", "head_manifest_sha256", "git_metadata",
)
_RECORD_FIELDS = {"record_type", "version", "approved", "reason", "before", "after", "paths"}
_REF_KEYS = ("gitdir:HEAD", "gitdir:refs", "common:packed-refs", "common:refs", "common:reftable")
_KINDS = {
    "capture-identity": "indirection", "git_dir": "indirection", "common_dir": "indirection",
    "worktree:.git": "indirection", "gitdir:commondir": "indirection", "gitdir:gitdir": "indirection",
    "gitdir:HEAD": "head", "gitdir:config.worktree": "config", "common:config": "config",
}
_KIND_PREFIXES = (
    ("config-file:", "config"), ("dependency:core.hookspath:", "hooks"),
    ("common:hooks", "hooks"), ("gitdir:info", "info"), ("common:info", "info"),
    ("gitdir:refs", "refs"), ("common:packed-refs", "refs"),
    ("common:refs", "refs"), ("common:reftable", "refs"),
)
_SCOPES = {"capture-identity": "capture", "git_dir": "per-worktree", "common_dir": "common"}
_SCOPE_PREFIXES = (("worktree:", "worktree"), ("gitdir:", "per-worktree"), ("common:", "common"))


def metadata_category(key: str) -> str:
    """Keep reference changes separate from other Git metadata."""
    return "git-refs" if any(key == ref or key.startswith(ref + "/") for ref in _REF_KEYS) else "git-metadata"


def _metadata_kind(key: str) -> str:
    if key in _KINDS:
        return _KINDS[key]
    for prefix, kind in _KIND_PREFIXES:
        if key == prefix or key.startswith(prefix + "/") or prefix.endswith(":") and key.startswith(prefix):
            return kind
    return "other"


def _metadata_scope(key: str) -> str:
    if key in _SCOPES:
        return _SCOPES[key]
    for prefix, scope in _SCOPE_PREFIXES:
        if key.startswith(prefix):
            return scope
    return "external"


def git_metadata_changes(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    """Changes to metadata, its dependencies and the bound indirection identities."""
    first, second = before.get("git_metadata"), after.get("git_metadata")
    if not isinstance(first, dict) or not isinstance(second, dict):
        return []
    changes = []
    for key in ("git_dir", "common_dir"):
        if first.get(key) != second.get(key):
            changes.append({"path": f".git:{key}", "before": first.get(key), "after": second.get(key), "category": "git-metadata"})
    identity_before, identity_after = before.get("capture_identity"), after.get("capture_identity")
    if identity_before and identity_after and identity_before != identity_after:
        changes.append({"path": ".git:capture-identity", "before": identity_before, "after": identity_after, "category": "git-metadata"})
    changes.extend(_entry_changes(first.get("entries"), second.get("entries")))
    return changes


def _entry_changes(first: Any, second: Any) -> list[dict[str, Any]]:
    if not isinstance(first, dict) or not isinstance(second, dict):
        return []
    if not all(isinstance(key, str) for key in set(first) | set(second)):
        return []
    return [
        {"path": f".git:{key}", "before": first.get(key), "after": second.get(key), "category": metadata_category(key)}
        for key in sorted(set(first) | set(second)) if first.get(key) != second.get(key)
    ]


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _valid_identity(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {"root", "git_dir", "common_dir"}:
        return False
    return all(isinstance(mark, list) and len(mark) == 3 and all(type(part) is int and part >= 0 for part in mark)
               for mark in value.values())


def _valid_metadata(value: Any) -> bool:
    if not isinstance(value, dict) or value.get("complete") is not True:
        return False
    if not all(isinstance(value.get(key), str) and value[key] for key in ("git_dir", "common_dir")):
        return False
    entries = value.get("entries")
    return isinstance(entries, dict) and bool(entries) and all(_valid_entry(key, entry) for key, entry in entries.items())


def _valid_entry(key: Any, value: Any) -> bool:
    if not isinstance(key, str) or not isinstance(value, dict):
        return False
    kind = value.get("kind")
    if kind == "absent":
        return set(value) == {"kind"}
    if kind not in {"file", "symlink", "directory"} or not _valid_mode(value.get("mode")):
        return False
    if kind == "directory":
        return set(value) == {"kind", "mode"}
    if kind == "symlink":
        return (set(value) == {"kind", "mode", "sha256", "referent"}
                and _valid_digest(value["sha256"], 64) and _valid_referent(value["referent"]))
    return set(value) == {"kind", "mode", "sha256"} and _valid_digest(value["sha256"], 64)


def _valid_mode(value: Any) -> bool:
    return type(value) is int and 0 <= value <= 0o7777


def _valid_digest(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(char in "0123456789abcdef" for char in value)


def _valid_referent(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    if value.get("kind") == "dangling":
        return set(value) == {"kind"}
    if value.get("kind") == "directory":
        identity = value.get("identity")
        return (set(value) == {"kind", "mode", "identity"} and _valid_mode(value["mode"])
                and isinstance(identity, list) and len(identity) == 2
                and all(type(part) is int and part >= 0 for part in identity))
    return value.get("kind") == "file" and _valid_entry("referent", value)


def _valid_capture(value: dict[str, Any]) -> bool:
    flags = (value.get("evidence_version") == 3 and type(value.get("evidence_version")) is int
             and value.get("is_git_repo") is True and value.get("baseline_complete") is True
             and value.get("incomplete") is False and not value.get("error") and not value.get("incomplete_reasons"))
    return bool(flags and _valid_binding({key: value.get(key) for key in BINDING_FIELDS}))


def _valid_binding(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != set(BINDING_FIELDS):
        return False
    return (_valid_identity(value["capture_identity"]) and _valid_metadata(value["git_metadata"])
            and _valid_executable(value["git_executable"]) and _valid_head(value)
            and _valid_digest(value["head_manifest_sha256"], 64))


def _valid_executable(value: Any) -> bool:
    return (isinstance(value, dict) and set(value) == {"path", "version"}
            and all(isinstance(part, str) and part for part in value.values()))


def _valid_head(value: dict[str, Any]) -> bool:
    lengths = {"sha1": 40, "sha256": 64}
    length = lengths.get(value["object_format"])
    return length is not None and (value["head"] is None or _valid_digest(value["head"], length))


def _record_header_error(record: Any) -> str | None:
    if not isinstance(record, dict) or set(record) != _RECORD_FIELDS:
        return "expected transition must have exactly the versioned record fields"
    if record["record_type"] != "expected-git-transition" or type(record["version"]) is not int or record["version"] != 1:
        return "unsupported expected transition record type or version"
    if record["approved"] is not True or not isinstance(record["reason"], str) or not record["reason"].strip():
        return "expected transition requires caller approval and a reason"
    return None


def _record_binding_error(record: dict[str, Any], before: dict[str, Any], after: dict[str, Any]) -> str | None:
    for name, evidence in (("before", before), ("after", after)):
        expected = record[name]
        if not _valid_binding(expected):
            return f"malformed {name} transition binding"
        actual = {key: evidence[key] for key in BINDING_FIELDS}
        if _canonical(expected) != _canonical(actual):
            return f"stale or changed {name} transition binding"
    if before["capture_identity"]["root"] != after["capture_identity"]["root"]:
        return "expected transition cannot approve workspace-root replacement or mode changes"
    return None


def _record_error(record: Any, before: dict[str, Any], after: dict[str, Any], changes: list[dict[str, Any]]) -> str | None:
    header = _record_header_error(record)
    if header:
        return header
    if not _valid_capture(before) or not _valid_capture(after):
        return "expected transitions require complete, well-formed version-3 captures"
    binding = _record_binding_error(record, before, after)
    if binding:
        return binding
    paths = record["paths"]
    changed_paths = {change["path"] for change in changes}
    if not isinstance(paths, list) or not paths or not all(isinstance(path, str) for path in paths):
        return "expected transition paths must be a nonempty list of exact changed paths"
    if len(set(paths)) != len(paths) or not set(paths) <= changed_paths:
        return "expected transition paths are duplicate, unchanged, unknown or wildcard paths"
    return None


def metadata_capture_incomplete(evidence: dict[str, Any], *, strict: bool = False) -> bool:
    """Only complete capture can establish authorization; keep legacy no-record comparisons compatible."""
    if strict:
        try:
            return not _valid_capture(evidence)
        except (TypeError, ValueError, KeyError, RecursionError):
            return True
    metadata = evidence.get("git_metadata")
    return bool(evidence.get("error") or evidence.get("incomplete") or not evidence.get("is_git_repo", True)
                or isinstance(metadata, dict) and metadata.get("complete") is False)


def _authorization(path: str, approved: set[str], incomplete: bool) -> str:
    if incomplete:
        return "incomplete"
    return "authorized" if path in approved else "unexplained"


def _classifications(changes: list[dict[str, Any]]) -> dict[str, list[str]]:
    return {status: [change["path"] for change in changes if change["authorization"] == status]
            for status in ("authorized", "unexplained", "incomplete")}


def compare_git_metadata(before: dict[str, Any], after: dict[str, Any], record: Any = None) -> dict[str, Any]:
    """Classify exact approved paths; a refused record never authorizes a change."""
    changes = git_metadata_changes(before, after)
    result = {"status": "not-supplied", "reason": None}
    approved: set[str] = set()
    incomplete = any(metadata_capture_incomplete(evidence, strict=record is not None) for evidence in (before, after))
    if record is not None:
        try:
            error = _record_error(record, before, after, changes)
        except (TypeError, ValueError, KeyError, RecursionError):
            error = "malformed expected transition or capture binding"
        result = {"status": "refused" if error else "accepted", "reason": error}
        if not error:
            approved = set(record["paths"])
    for change in changes:
        key = change["path"].removeprefix(".git:")
        change.update(metadata_kind=_metadata_kind(key), metadata_scope=_metadata_scope(key),
                      authorization=_authorization(change["path"], approved, incomplete))
    return {"changes": changes, "record": result, "incomplete": incomplete, "classifications": _classifications(changes)}


def mutation_is_allowed(item: dict[str, Any]) -> bool:
    return item.get("category") == "scoped" or item.get("authorization") == "authorized"


def unexpected_mutations(mutations: list[dict[str, Any]], transition: dict[str, Any]) -> list[dict[str, Any]]:
    unexpected = [item for item in mutations if item["category"] in {
        "out-of-scope", "untracked", "attribution-ambiguous", "git-metadata", "git-refs",
    } and item.get("authorization") != "authorized"]
    if transition["record"]["status"] == "refused":
        unexpected.append({"path": ".git:expected-transition", "category": "expected-transition-refused",
                           "before": None, "after": transition["record"]["reason"]})
    return unexpected
