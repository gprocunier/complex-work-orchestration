#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import errno
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

from cwo_core.util import atomic_write_text


SKILL_NAME = "complex-work-orchestration"
INSTALL_MANIFEST_NAME = ".cwo-install-manifest.json"
INSTALL_RECORD_TYPE = "cwo-installed-skill-status"
INSTALL_RECORD_VERSION = 2
READABLE_INSTALL_RECORD_VERSIONS = (1, 2)
# The installed projection: the one list of what is installed, read by scripts/install.sh
# (through --list-entries and --list-files) and by the drift check below.
PROJECTION_PATH = "policy/install-projection.yaml"
PROJECTION_VERSION = 1
PROJECTION_KEYS = {"version", "description", "skill_name", "entries", "excluded"}
PROJECTION_KINDS = {"file", "directory"}
PROJECTION_PATH_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]*(?:/[A-Za-z0-9_][A-Za-z0-9._-]*)*")
EXCLUDED_PATH_RE = re.compile(r"\.?[A-Za-z0-9_][A-Za-z0-9._-]*")
IGNORED_DIR_NAMES = {"__pycache__"}
IGNORED_SUFFIXES = {".pyc", ".pyo"}
IGNORED_FILE_NAMES = {INSTALL_MANIFEST_NAME, ".DS_Store"}
CALIBRATION_ARTIFACTS = {
    "contract": "calibration/skl-return-language-contract-v1.json",
    "corpus": "calibration/skl-return-language-corpus-v1.json",
    "tuning": "calibration/skl-return-language-tuning-v1.json",
    "latest_report": "calibration/skl-return-language-calibration-report-latest.json",
}
# Errors that mean "this path is absent or one of its components is a symbolic link or not a
# directory"; anything else while reading a projection (permission, I/O) refuses.
ABSENT_ERRNOS = {errno.ENOENT, errno.ENOTDIR}
NOT_FOLLOWED_ERRNOS = ABSENT_ERRNOS | {errno.ELOOP, errno.EMLINK}
VERSION_READ_LIMIT = 4096
REPO_ROOT = Path(__file__).resolve().parents[1]


class ProjectionError(ValueError):
    """The installed projection is malformed, or a source tree does not satisfy it."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reason(exc: OSError) -> str:
    return exc.strerror or str(exc)


def _open_regular_nofollow(root: Path, relative: str) -> int | None:
    """Open root/relative for reading without following a symbolic link below root.

    Every component under root is opened relative to its parent with O_NOFOLLOW, so a symbolic
    link anywhere along the path is never followed and its target is never opened. Returns a
    descriptor for a regular file, or None when a component is missing, is a symbolic link or is
    not a directory, or the file is not regular. Any other error raises ProjectionError. root
    itself is the directory the caller chose and is opened as given.
    """
    parts = relative.split("/")
    try:
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno in ABSENT_ERRNOS:
            return None
        raise ProjectionError(f"cannot open {root}: {_reason(exc)}") from None
    try:
        for name in parts[:-1]:
            try:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            except OSError as exc:
                if exc.errno in NOT_FOLLOWED_ERRNOS:
                    return None
                raise ProjectionError(f"cannot read projection path {relative}: {_reason(exc)}") from None
            os.close(directory)
            directory = child
        try:
            # O_NONBLOCK: opening a FIFO that replaced a file must not wait for a writer.
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        except OSError as exc:
            if exc.errno in NOT_FOLLOWED_ERRNOS:
                return None
            raise ProjectionError(f"cannot read projection file {relative}: {_reason(exc)}") from None
    finally:
        os.close(directory)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        return None
    return fd


def _hash_regular_nofollow(root: Path, relative: str, *, keep: int = 0) -> tuple[str, int, bytes] | None:
    """SHA-256 and size of a regular file read without following links; None when not regular.

    keep returns up to that many leading bytes of the content as well.
    """
    fd = _open_regular_nofollow(root, relative)
    if fd is None:
        return None
    digest = hashlib.sha256()
    size = 0
    head = b""
    try:
        with os.fdopen(fd, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
                if len(head) < keep:
                    head += chunk[: keep - len(head)]
    except OSError as exc:
        raise ProjectionError(f"cannot read projection file {relative}: {_reason(exc)}") from None
    return digest.hexdigest(), size, head


def _read_regular_nofollow(root: Path, relative: str) -> bytes | None:
    fd = _open_regular_nofollow(root, relative)
    if fd is None:
        return None
    try:
        with os.fdopen(fd, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise ProjectionError(f"cannot read projection file {relative}: {_reason(exc)}") from None


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate key {key!r}")
        value[key] = item
    return value


def ignored_path(path: Path) -> bool:
    if path.name in IGNORED_FILE_NAMES:
        return True
    if path.suffix in IGNORED_SUFFIXES:
        return True
    return any(part in IGNORED_DIR_NAMES for part in path.parts)


def _covers(entry: str, path: str) -> bool:
    return path == entry or path.startswith(entry + "/")


def _overlaps(first: str, second: str) -> bool:
    return _covers(first, second) or _covers(second, first)


def load_projection(source_root: Path) -> dict[str, Any]:
    """Load and validate the installed projection a source tree declares."""
    path = source_root / PROJECTION_PATH
    # Read without following a symbolic link at any component (policy/ included).
    data = _read_regular_nofollow(source_root, PROJECTION_PATH)
    if data is None:
        raise ProjectionError(f"installed projection is missing or not a regular file: {path}")
    where = PROJECTION_PATH
    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_keys)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ProjectionError(
            f"{path} is not JSON-compatible YAML: {exc}. Policy files use a strict JSON-compatible YAML subset."
        ) from None
    if not isinstance(document, dict):
        raise ProjectionError(f"{where} must contain a top-level object")
    if set(document) != PROJECTION_KEYS:
        raise ProjectionError(f"{where} must have exactly the keys {sorted(PROJECTION_KEYS)}")
    if isinstance(document["version"], bool) or document["version"] != PROJECTION_VERSION:
        raise ProjectionError(f"{where} version must be {PROJECTION_VERSION}")
    if document["skill_name"] != SKILL_NAME:
        raise ProjectionError(f"{where} skill_name must be {SKILL_NAME!r}")
    if not isinstance(document["description"], str) or not document["description"].strip():
        raise ProjectionError(f"{where} description must be a non-empty string")
    entries = document["entries"]
    if not isinstance(entries, list) or not entries:
        raise ProjectionError(f"{where} entries must be a non-empty list")
    seen: list[str] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {"path", "kind"}:
            raise ProjectionError(f"{where} entries[{index}] must have exactly the keys kind and path")
        value = entry["path"]
        if not isinstance(value, str) or not PROJECTION_PATH_RE.fullmatch(value):
            raise ProjectionError(
                f"{where} entries[{index}].path {value!r} must be a relative POSIX path of letters, digits, "
                "'.', '_' and '-' with no empty, hidden or parent components"
            )
        if not isinstance(entry["kind"], str) or entry["kind"] not in PROJECTION_KINDS:
            raise ProjectionError(f"{where} entries[{index}].kind must be file or directory")
        for other in seen:
            if _overlaps(value, other):
                raise ProjectionError(f"{where} entries {other!r} and {value!r} overlap")
        seen.append(value)
    if not any(_covers(item, PROJECTION_PATH) for item in seen):
        raise ProjectionError(f"{where} must be inside the projection it declares")
    excluded = document["excluded"]
    if not isinstance(excluded, list):
        raise ProjectionError(f"{where} excluded must be a list")
    for index, entry in enumerate(excluded):
        if not isinstance(entry, dict) or set(entry) != {"path", "reason"}:
            raise ProjectionError(f"{where} excluded[{index}] must have exactly the keys path and reason")
        value = entry["path"]
        if not isinstance(value, str) or not EXCLUDED_PATH_RE.fullmatch(value):
            raise ProjectionError(f"{where} excluded[{index}].path {value!r} must be one top-level name")
        if not isinstance(entry["reason"], str) or not entry["reason"].strip():
            raise ProjectionError(f"{where} excluded[{index}].reason must be a non-empty string")
        for other in seen:
            if _overlaps(value, other):
                raise ProjectionError(f"{where} excluded path {value!r} overlaps entry {other!r}")
    return {**document, "projection_sha256": sha256_bytes(data)}


def projection_identity(projection: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": PROJECTION_PATH,
        "version": projection["version"],
        "sha256": projection["projection_sha256"],
        "entries": [entry["path"] for entry in projection["entries"]],
    }


def _lstat(path: Path, relative: str) -> os.stat_result | None:
    try:
        return path.lstat()
    except OSError as exc:
        if exc.errno in ABSENT_ERRNOS:
            return None
        raise ProjectionError(f"cannot read projection path {relative}: {_reason(exc)}") from None


def entry_kind(root: Path, item: str) -> str:
    """What is at root/item, checking every component without following links.

    Returns file, directory, symlink (the entry or a parent component is a symbolic link), other
    (a special file) or missing (absent, or a parent component is not a directory).
    """
    current = root
    parts = item.split("/")
    for index, name in enumerate(parts):
        current = current / name
        info = _lstat(current, item)
        if info is None:
            return "missing"
        if stat.S_ISLNK(info.st_mode):
            return "symlink"
        if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            return "missing"
    if stat.S_ISREG(info.st_mode):
        return "file"
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    return "other"


def iter_manifest_files(
    root: Path, projection: dict[str, Any], *, strict: bool = True
) -> list[tuple[str, Path | None]]:
    """Enumerate the files of the projection under root.

    strict (a source tree) refuses a missing entry, an entry of the wrong kind, a symbolic link
    or a special file. Otherwise (an installed tree) a missing entry contributes no files, and
    anything that is not a regular file is returned without a path so it reads as drift. On
    both sides a directory that cannot be listed or a path that cannot be examined refuses with
    ProjectionError: a traversal error never shortens the enumeration.
    """
    found: list[tuple[str, Path | None]] = []

    def irregular(relative: str, message: str) -> None:
        if strict:
            raise ProjectionError(f"{message}: {relative}")
        found.append((relative, None))

    def walk(directory: Path, relative: str) -> None:
        try:
            with os.scandir(directory) as iterator:
                names = sorted(child.name for child in iterator)
        except OSError as exc:
            raise ProjectionError(f"cannot read projection directory {relative}: {_reason(exc)}") from None
        for name in names:
            child = directory / name
            text = f"{relative}/{name}"
            info = _lstat(child, text)
            if info is None:
                raise ProjectionError(f"projection path changed while it was read: {text}")
            mode = info.st_mode
            if stat.S_ISDIR(mode):
                if name in IGNORED_DIR_NAMES:
                    continue
            elif ignored_path(Path(text)):
                continue
            if any(ord(char) < 32 or char in "\\\x7f" for char in text):
                raise ProjectionError(f"projection path contains a control character or backslash: {text!r}")
            if stat.S_ISDIR(mode):
                walk(child, text)
            elif stat.S_ISREG(mode):
                found.append((text, child))
            elif stat.S_ISLNK(mode):
                irregular(text, "projection contains a symbolic link")
            else:
                irregular(text, "projection contains a special file")

    for entry in projection["entries"]:
        item, kind = entry["path"], entry["kind"]
        actual = entry_kind(root, item)
        if actual == "symlink":
            irregular(item, "projection entry is a symbolic link")
            continue
        if actual == "missing":
            if strict:
                raise ProjectionError(f"required projection entry missing: {item}")
            continue
        if kind == "file":
            if actual == "file":
                found.append((item, root / item))
            else:
                irregular(item, "projection entry must be a regular file")
            continue
        if actual != "directory":
            irregular(item, "projection entry must be a directory")
            continue
        walk(root / item, item)
    return sorted(found, key=lambda item: item[0])


def build_manifest(
    root: Path, projection: dict[str, Any] | None = None, *, strict: bool = True
) -> dict[str, Any]:
    if projection is None:
        projection = load_projection(root)
    files: list[dict[str, Any]] = []
    version_bytes: bytes | None = None
    for relative, path in iter_manifest_files(root, projection, strict=strict):
        hashed = None
        if path is not None:
            # Content and metadata come only from files the enumeration validated, read without
            # following a link at any component.
            hashed = _hash_regular_nofollow(root, relative, keep=VERSION_READ_LIMIT if relative == "VERSION" else 0)
            if hashed is None and strict:
                raise ProjectionError(f"projection file is no longer a regular file: {relative}")
        if hashed is not None and relative == "VERSION":
            version_bytes = hashed[2]
        files.append({
            "path": relative,
            "sha256": hashed[0] if hashed is not None else None,
            "size": hashed[1] if hashed is not None else None,
        })
    # Every entry is checked for presence and kind on its own, so an entry with no files (an
    # empty required directory) is still compared.
    entries = [
        {"path": entry["path"], "kind": entry["kind"], "found": entry_kind(root, entry["path"])}
        for entry in projection["entries"]
    ]
    skill_version = None
    if version_bytes is not None:
        skill_version = version_bytes.decode("utf-8", errors="replace").strip() or None
    payload = "\n".join(f"{item['path']}\0{item['sha256']}\0{item['size']}" for item in files)
    return {
        "manifest_type": "cwo-skill-content-manifest",
        "version": 1,
        "skill_name": SKILL_NAME,
        "skill_version": skill_version,
        "projection": projection_identity(projection),
        "content_sha256": sha256_bytes(payload.encode("utf-8")),
        "file_count": len(files),
        "files": files,
        "entries": entries,
    }


def _calibration_artifacts(manifest: dict[str, Any]) -> dict[str, Any]:
    """Calibration artifact hashes taken from a manifest's validated regular files only."""
    hashes = {item["path"]: item.get("sha256") for item in manifest.get("files", [])}
    return {key: hashes.get(path) for key, path in CALIBRATION_ARTIFACTS.items()}


def compare_manifests(source: dict[str, Any], installed: dict[str, Any]) -> dict[str, Any]:
    source_files = {item["path"]: item for item in source.get("files", [])}
    installed_files = {item["path"]: item for item in installed.get("files", [])}
    missing = sorted(set(source_files) - set(installed_files))
    extra = sorted(set(installed_files) - set(source_files))
    changed = sorted(
        path
        for path in set(source_files) & set(installed_files)
        if source_files[path].get("sha256") != installed_files[path].get("sha256")
        or source_files[path].get("size") != installed_files[path].get("size")
    )
    found = {item["path"]: item.get("found") for item in installed.get("entries", [])}
    expected = {item["path"]: item.get("kind") for item in source.get("entries", [])}
    missing_entries = sorted(path for path in expected if found.get(path, "missing") == "missing")
    mismatched_entries = sorted(
        path for path, kind in expected.items() if found.get(path, "missing") not in ("missing", kind)
    )
    current = (
        not missing and not extra and not changed and not missing_entries and not mismatched_entries
        and source.get("content_sha256") == installed.get("content_sha256")
    )
    return {
        "status": "current" if current else "drift",
        "source_version": source.get("skill_version"),
        "installed_version": installed.get("skill_version"),
        "source_content_sha256": source.get("content_sha256"),
        "installed_content_sha256": installed.get("content_sha256"),
        "source_file_count": source.get("file_count"),
        "installed_file_count": installed.get("file_count"),
        "missing_files": missing,
        "extra_files": extra,
        "changed_files": changed,
        "missing_entries": missing_entries,
        "mismatched_entries": mismatched_entries,
    }


def read_install_record(target_dir: Path) -> dict[str, Any] | None:
    """Summarize an existing install record of any readable version; informational only."""
    path = target_dir / INSTALL_MANIFEST_NAME
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        return {"readable": False, "error": str(exc)}
    try:
        data = _read_regular_nofollow(target_dir, INSTALL_MANIFEST_NAME) if stat.S_ISREG(info.st_mode) else None
        if data is None:
            raise ValueError("not a regular file")
        record = json.loads(data.decode("utf-8"))
        if not isinstance(record, dict) or record.get("manifest_type") != INSTALL_RECORD_TYPE:
            raise ValueError(f"manifest_type is not {INSTALL_RECORD_TYPE}")
        version = record.get("version")
        if isinstance(version, bool) or version not in READABLE_INSTALL_RECORD_VERSIONS:
            raise ValueError(f"unsupported version {version!r}")
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return {"readable": False, "error": str(exc)}
    projection = record.get("projection") if version >= 2 else None
    return {
        "readable": True,
        "version": version,
        "status": record.get("status"),
        "installed_content_sha256": record.get("installed_content_sha256"),
        "projection_sha256": projection.get("sha256") if isinstance(projection, dict) else None,
    }


def _record_check_result(target_dir: Path | str) -> dict[str, Any]:
    return {
        "skill_name": SKILL_NAME,
        "installed_dir": str(target_dir),
        "status": "record-unverifiable",
        "verification_scope": (
            "Local self-consistency only: the local record and installed bytes both can be rewritten. "
            "This is not provenance, authentication, admission or activation readiness. "
            "No active activation consumer uses this status."
        ),
        "errors": [],
    }


def _validate_record_metadata(record: Any) -> None:
    required = {
        "manifest_type", "version", "generated_at", "skill_name", "status", "source_dir",
        "projection", "source_version", "installed_version",
        "source_content_sha256", "installed_content_sha256",
        "source_file_count", "installed_file_count", "calibration_artifacts",
    }
    if not isinstance(record, dict) or not required <= record.keys():
        raise ValueError("record must contain the version 2 install record fields")
    if record["manifest_type"] != INSTALL_RECORD_TYPE or record["skill_name"] != SKILL_NAME:
        raise ValueError("record manifest_type or skill_name is invalid")
    if type(record["version"]) is not int or record["version"] != INSTALL_RECORD_VERSION:
        raise ValueError("record version must be integer 2")
    if record["status"] != "current":
        raise ValueError("record must describe a current source-comparison result")
    if not isinstance(record["generated_at"], str) or not record["generated_at"].strip():
        raise ValueError("record generated_at must be a non-empty string")
    if record["source_dir"] is not None and not isinstance(record["source_dir"], str):
        raise ValueError("record source_dir must be a string or null; it is never followed")


def _validate_record_versions(record: dict[str, Any]) -> None:
    for key in ("source_version", "installed_version"):
        value = record[key]
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise ValueError(f"record {key} must be a non-empty string or null")
    if record["source_version"] != record["installed_version"]:
        raise ValueError("current record versions must agree")


def _valid_record_hash(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _validate_record_content(record: dict[str, Any]) -> None:
    for key in ("source_content_sha256", "installed_content_sha256"):
        if not _valid_record_hash(record[key]):
            raise ValueError(f"record {key} must be a lowercase SHA-256 digest")
    for key in ("source_file_count", "installed_file_count"):
        if type(record[key]) is not int or record[key] < 0:
            raise ValueError(f"record {key} must be a nonnegative integer")
    if record["source_content_sha256"] != record["installed_content_sha256"] or (
        record["source_file_count"] != record["installed_file_count"]
    ):
        raise ValueError("current record source and installed hashes/counts must agree")


def _validate_record_projection_entries(entries: Any) -> None:
    if not isinstance(entries, list) or not entries:
        raise ValueError("record projection entries must be a non-empty list")
    seen: list[str] = []
    for path in entries:
        if not isinstance(path, str) or not PROJECTION_PATH_RE.fullmatch(path):
            raise ValueError("record projection entries must be valid relative projection paths")
        if any(_overlaps(path, other) for other in seen):
            raise ValueError("record projection entries must not overlap")
        seen.append(path)


def _validate_record_projection(projection: Any) -> None:
    if not isinstance(projection, dict) or set(projection) != {"path", "version", "sha256", "entries"}:
        raise ValueError("record projection must contain exactly path, version, sha256 and entries")
    if projection["path"] != PROJECTION_PATH or type(projection["version"]) is not int:
        raise ValueError("record projection path or version type is invalid")
    if projection["version"] != PROJECTION_VERSION or not _valid_record_hash(projection["sha256"]):
        raise ValueError("record projection version or SHA-256 digest is invalid")
    _validate_record_projection_entries(projection["entries"])


def _validate_record_artifacts(artifacts: Any) -> None:
    if not isinstance(artifacts, dict) or set(artifacts) != {"source", "installed"}:
        raise ValueError("record calibration_artifacts must contain source and installed")
    for side in ("source", "installed"):
        values = artifacts[side]
        if not isinstance(values, dict) or set(values) != set(CALIBRATION_ARTIFACTS):
            raise ValueError(f"record calibration_artifacts.{side} has invalid keys")
        if any(value is not None and not _valid_record_hash(value) for value in values.values()):
            raise ValueError(f"record calibration_artifacts.{side} contains an invalid hash")
    if artifacts["source"] != artifacts["installed"]:
        raise ValueError("current record calibration hashes must agree")


def _validate_record_for_check(record: Any) -> dict[str, Any]:
    _validate_record_metadata(record)
    _validate_record_versions(record)
    _validate_record_content(record)
    _validate_record_projection(record["projection"])
    _validate_record_artifacts(record["calibration_artifacts"])
    return record


def _record_manifest_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "installed_content_sha256": manifest["content_sha256"],
        "installed_file_count": manifest["file_count"],
        "installed_version": manifest["skill_version"],
        "missing_entries": [
            entry["path"] for entry in manifest["entries"] if entry["found"] == "missing"
        ],
        "mismatched_entries": [
            entry["path"] for entry in manifest["entries"] if entry["found"] not in ("missing", entry["kind"])
        ],
        "missing_files": [
            entry["path"] for entry in manifest["entries"]
            if entry["kind"] == "file" and entry["found"] == "missing"
        ],
        "invalid_files": [
            item["path"] for item in manifest["files"] if item["sha256"] is None
        ],
    }


def _compare_record_manifest(record: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    result = _record_manifest_summary(manifest)
    checks = [
        (manifest["content_sha256"] != record["installed_content_sha256"], "content-aggregate-mismatch", "Installed file bytes or file inventory differ from the retained aggregate."),
        (manifest["file_count"] != record["installed_file_count"], "file-count-mismatch", "Installed file count differs from the retained record."),
        (bool(result["missing_entries"]), "missing-required-entry", "Required projection entries are missing."),
        (bool(result["mismatched_entries"]), "entry-kind-mismatch", "Required projection entries have the wrong kind."),
        (bool(result["invalid_files"]), "invalid-installed-file", "Projected files include links, special files or files that ceased to be regular."),
        (manifest["skill_version"] != record["installed_version"], "installed-version-mismatch", "Installed VERSION differs from the retained record."),
        (
            _calibration_artifacts(manifest) != record["calibration_artifacts"]["installed"],
            "calibration-artifacts-mismatch",
            "Installed calibration hashes differ from the retained record.",
        ),
    ]
    result["errors"] = [
        {"code": code, "message": message} for changed, code, message in checks if changed
    ]
    result["status"] = "record-drift" if result["errors"] else "record-consistent"
    return result


def record_check_status(target_dir: Path) -> dict[str, Any]:
    """Check local retained-record self-consistency without consulting a source checkout."""
    result = _record_check_result(target_dir)

    def refuse(code: str, message: str) -> dict[str, Any]:
        result["errors"].append({"code": code, "message": message})
        return result

    try:
        data = _read_regular_nofollow(target_dir, INSTALL_MANIFEST_NAME)
        if data is None:
            kind = entry_kind(target_dir, INSTALL_MANIFEST_NAME)
            code = "record-missing" if kind == "missing" else "record-not-regular"
            return refuse(code, f"Install record is {kind}; a regular retained record is required.")
    except (ProjectionError, OSError) as exc:
        return refuse("record-unreadable", str(exc))
    try:
        record = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_keys)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        return refuse("invalid-record", str(exc))
    if isinstance(record, dict) and type(record.get("version")) is int and record["version"] != 2:
        result["record_version"] = record["version"]
        return refuse("unsupported-record-version", f"Record version {record['version']} cannot verify this mode.")
    try:
        record = _validate_record_for_check(record)
    except ValueError as exc:
        return refuse("invalid-record", str(exc))
    result.update({
        "record_version": record["version"],
        "recorded_projection": record["projection"],
        "recorded_content_sha256": record["installed_content_sha256"],
        "recorded_file_count": record["installed_file_count"],
    })
    try:
        projection = load_projection(target_dir)
        if type(projection["version"]) is not int:
            raise ProjectionError("installed projection version must be an integer")
    except (ProjectionError, OSError, RecursionError) as exc:
        return refuse("installed-projection-unverifiable", str(exc))
    result["projection"] = projection_identity(projection)
    if result["projection"] != record["projection"]:
        result["status"] = "record-drift"
        return refuse("projection-mismatch", "Installed projection differs from the retained record; enumeration refused.")
    try:
        manifest = build_manifest(target_dir, projection, strict=False)
    except (ProjectionError, OSError, RecursionError, UnicodeError) as exc:
        return refuse("installed-unreadable", str(exc))
    result.update(_compare_record_manifest(record, manifest))
    return result


def render_record_check(status: dict[str, Any]) -> str:
    lines = [
        f"Skill install record status: {status['status']}",
        f"  Installed: {status['installed_dir']}",
        f"  Scope: {status['verification_scope']}",
    ]
    for issue in status["errors"]:
        lines.append(f"  {issue['code']}: {issue['message']}")
    return "\n".join(lines)


def default_codex_home() -> Path:
    return Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex").expanduser()


def default_skills_dir() -> Path:
    if os.environ.get("CODEX_SKILLS_DIR"):
        return Path(os.environ["CODEX_SKILLS_DIR"]).expanduser()
    return default_codex_home() / "skills"


def resolve_target_dir(args: argparse.Namespace) -> Path:
    if args.installed_dir:
        return Path(args.installed_dir).expanduser().resolve()
    if args.skills_dir:
        return (Path(args.skills_dir).expanduser() / SKILL_NAME).resolve()
    if args.codex_home:
        return (Path(args.codex_home).expanduser() / "skills" / SKILL_NAME).resolve()
    return (default_skills_dir() / SKILL_NAME).resolve()


def installed_status(source_dir: Path, target_dir: Path) -> dict[str, Any]:
    projection = load_projection(source_dir)
    source_manifest = build_manifest(source_dir, projection)
    result: dict[str, Any] = {
        "skill_name": SKILL_NAME,
        "source_dir": str(source_dir),
        "installed_dir": str(target_dir),
        "projection": source_manifest["projection"],
    }
    if not target_dir.exists():
        result.update(
            {
                "status": "missing",
                "source_version": source_manifest.get("skill_version"),
                "installed_version": None,
                "source_content_sha256": source_manifest.get("content_sha256"),
                "installed_content_sha256": None,
                "source_file_count": source_manifest.get("file_count"),
                "installed_file_count": 0,
                "calibration_artifacts": {
                    "source": _calibration_artifacts(source_manifest),
                    "installed": {},
                },
                "previous_install_record": None,
                "missing_files": [item["path"] for item in source_manifest.get("files", [])],
                "extra_files": [],
                "changed_files": [],
                "missing_entries": [item["path"] for item in source_manifest.get("entries", [])],
                "mismatched_entries": [],
            }
        )
        return result
    installed_manifest = build_manifest(target_dir, projection, strict=False)
    result["calibration_artifacts"] = {
        "source": _calibration_artifacts(source_manifest),
        "installed": _calibration_artifacts(installed_manifest),
    }
    result["previous_install_record"] = read_install_record(target_dir)
    result.update(compare_manifests(source_manifest, installed_manifest))
    return result


def write_install_manifest(target_dir: Path, status: dict[str, Any]) -> Path:
    manifest_path = target_dir / INSTALL_MANIFEST_NAME
    payload = {
        "manifest_type": INSTALL_RECORD_TYPE,
        "version": INSTALL_RECORD_VERSION,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "skill_name": SKILL_NAME,
        "status": status["status"],
        "source_dir": status.get("source_dir"),
        "projection": status.get("projection"),
        "source_version": status.get("source_version"),
        "installed_version": status.get("installed_version"),
        "source_content_sha256": status.get("source_content_sha256"),
        "installed_content_sha256": status.get("installed_content_sha256"),
        "source_file_count": status.get("source_file_count"),
        "installed_file_count": status.get("installed_file_count"),
        "calibration_artifacts": status.get("calibration_artifacts"),
    }
    atomic_write_text(manifest_path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return manifest_path


def render_text(status: dict[str, Any]) -> str:
    projection = status.get("projection") or {}
    lines = [
        f"Skill install status: {status['status']}",
        f"  Source: {status['source_dir']}",
        f"  Installed: {status['installed_dir']}",
        f"  Projection: {projection.get('path')} sha256 {projection.get('sha256')}",
        f"  Source version: {status.get('source_version') or 'unknown'}",
        f"  Installed version: {status.get('installed_version') or 'unknown'}",
        f"  Source hash: {status.get('source_content_sha256') or 'missing'}",
        f"  Installed hash: {status.get('installed_content_sha256') or 'missing'}",
    ]
    record = status.get("previous_install_record")
    if record:
        if record.get("readable"):
            lines.append(f"  Existing install record: version {record['version']}, recorded status {record.get('status')}")
        else:
            lines.append(f"  Existing install record: unreadable ({record.get('error')})")
    for label, key in [
        ("Missing entries", "missing_entries"),
        ("Entries of the wrong kind", "mismatched_entries"),
        ("Missing files", "missing_files"),
        ("Changed files", "changed_files"),
        ("Extra files", "extra_files"),
    ]:
        values = status.get(key) or []
        if values:
            lines.append(f"  {label}:")
            for value in values[:20]:
                lines.append(f"    - {value}")
            if len(values) > 20:
                lines.append(f"    - ... {len(values) - 20} more")
    if status["status"] != "current":
        lines.append("  Reload: ./scripts/install.sh --skills-dir <codex-skills-dir> --yes")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check installed complex-work-orchestration skill drift.")
    parser.add_argument("--source-dir", default=str(REPO_ROOT), help="Source repository root. Defaults to this checkout.")
    parser.add_argument("--skills-dir", help="Codex skills directory containing the skill.")
    parser.add_argument("--codex-home", help="Codex home directory containing skills/.")
    parser.add_argument("--installed-dir", help="Direct path to an installed complex-work-orchestration skill.")
    parser.add_argument(
        "--record-check", action="store_true",
        help="Read-only retained v2 record self-consistency check; nonzero for drift or unverifiable records.",
    )
    parser.add_argument("--write-manifest", action="store_true", help=f"Write {INSTALL_MANIFEST_NAME} into the installed skill.")
    parser.add_argument("--check", action="store_true", help="Exit nonzero when the installed skill is missing or drifted.")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of human-readable text.")
    listing = parser.add_mutually_exclusive_group()
    listing.add_argument(
        "--list-entries", action="store_true",
        help=f"Validate the source against {PROJECTION_PATH} and print its entries, one per line.",
    )
    listing.add_argument(
        "--list-files", action="store_true",
        help=f"Validate the source against {PROJECTION_PATH} and print every file to install, one per line.",
    )
    listing.add_argument(
        "--list-directories", action="store_true",
        help=f"Validate the source against {PROJECTION_PATH} and print its directory entries, one per line.",
    )
    args = parser.parse_args()
    if args.record_check and (
        args.write_manifest or args.list_entries or args.list_files or args.list_directories
    ):
        parser.error("--record-check cannot be combined with --write-manifest or projection listing flags")
    return args


def _print_check_status(
    status: dict[str, Any], *, as_json: bool, record_check: bool = False
) -> None:
    if as_json:
        print(json.dumps(status, indent=2, sort_keys=True))
    elif record_check:
        print(render_record_check(status))
    else:
        print(render_text(status))


def _run_record_check(args: argparse.Namespace) -> int:
    try:
        target_dir = resolve_target_dir(args)
    except (OSError, RuntimeError, ValueError) as exc:
        status = _record_check_result(args.installed_dir or "<unresolved target>")
        status["errors"].append({"code": "installed-target-unreadable", "message": str(exc)})
    else:
        status = record_check_status(target_dir)
    _print_check_status(status, as_json=args.json, record_check=True)
    return {
        "record-consistent": 0,
        "record-drift": 1,
        "record-unverifiable": 2,
    }[status["status"]]


def main() -> int:
    args = parse_args()
    if args.record_check:
        return _run_record_check(args)
    source_dir = Path(args.source_dir).expanduser().resolve()
    try:
        if args.list_entries or args.list_files or args.list_directories:
            projection = load_projection(source_dir)
            files = iter_manifest_files(source_dir, projection)
            if args.list_entries:
                lines = [entry["path"] for entry in projection["entries"]]
            elif args.list_directories:
                lines = [entry["path"] for entry in projection["entries"] if entry["kind"] == "directory"]
            else:
                lines = [relative for relative, _ in files]
            sys.stdout.write("".join(f"{line}\n" for line in lines))
            return 0
        target_dir = resolve_target_dir(args)
        status = installed_status(source_dir, target_dir)
    except ProjectionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.write_manifest and target_dir.exists():
        status["install_manifest_path"] = str(write_install_manifest(target_dir, status))
    _print_check_status(status, as_json=args.json)
    if args.check and status["status"] != "current":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
