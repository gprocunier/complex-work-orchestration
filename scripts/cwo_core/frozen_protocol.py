"""Fail-closed locks for already-frozen experimental protocols.

The lock separates execution-critical bindings from authoring provenance.
Execution bindings are verified live before release.  Provenance digests record
what informed protocol authoring, but later changes to those contextual files do
not silently invalidate an otherwise immutable execution contract.

This module also classifies Python bytecode generated beneath sealed trees.
Cleanup is intentionally narrow: only ordinary ``*.pyc`` files directly under
ordinary ``__pycache__`` directories are removable.  Symlinks, nested
directories, or mixed content fail closed.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Any, Mapping


LOCK_SCHEMA = "cwo-frozen-protocol-lock:v1"
RUN_SCHEMA = "cwo-frozen-protocol-run:v1"
PROTOCOL_READY = "protocol-ready"
PROTOCOL_BLOCKED = "protocol-blocked"
NEW_PROTOCOL_REQUIRED = "new-protocol-required"

LOCK_FIELDS = frozenset(
    {
        "schema_version",
        "protocol_id",
        "governing_prompt",
        "execution_bindings",
        "run_contract",
        "authoring_provenance",
        "lock_sha256",
    }
)
FILE_BINDING_FIELDS = frozenset({"label", "path", "sha256"})
RUN_CONTRACT_FIELDS = frozenset(
    {
        "scenario_count",
        "arms",
        "initial_cells",
        "compatibility_smoke_cells",
        "confirmation_max_cells",
        "retry_limit",
        "decision_rule_sha256",
        "immutable_fields",
        "forbidden_substitutions",
    }
)
RUN_FIELDS = frozenset(
    {"schema_version", "protocol_id", "lock_sha256", "run_contract", "steering"}
)
STEERING_FIELDS = frozenset(
    {
        "classification",
        "instruction_sha256",
        "changed_locked_fields",
        "replacement_authorization_sha256",
        "repair_class",
    }
)

REQUIRED_EXECUTION_LABELS = frozenset({"controller", "manifest"})
REQUIRED_IMMUTABLE_FIELDS = frozenset(
    {
        "controller",
        "manifest",
        "tasks",
        "prompts",
        "scoring",
        "thresholds",
        "budget",
        "decision-rule",
    }
)
REQUIRED_FORBIDDEN_SUBSTITUTIONS = frozenset(
    {"benchmark-replacement", "task-family-replacement", "controller-replacement"}
)
STEERING_CLASSES = frozenset(
    {"continue", "same-scope-repair", "replace-protocol"}
)
SAME_SCOPE_REPAIR_CLASSES = frozenset(
    {
        "mechanical-derived-cache",
        "mechanical-permission-restoration",
        "controller-transport",
        "stale-verifier",
    }
)


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonical_lock_sha256(value: Mapping[str, Any]) -> str:
    payload = deepcopy(dict(value))
    payload.pop("lock_sha256", None)
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def seal_frozen_protocol_lock(value: Mapping[str, Any]) -> dict[str, Any]:
    payload = deepcopy(dict(value))
    payload["lock_sha256"] = canonical_lock_sha256(payload)
    return payload


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _exact_fields(
    value: Any,
    expected: frozenset[str],
    path: str,
    errors: list[str],
) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        errors.append(f"{path} must be an object")
        return None
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing:
        errors.append(f"{path} missing field(s): {', '.join(missing)}")
    if extra:
        errors.append(f"{path} has unknown field(s): {', '.join(extra)}")
    return value


def _nonempty_string(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{path} must be a non-empty string")


def _relative_path(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value:
        errors.append(f"{path} must be a non-empty relative POSIX path")
        return
    if "\\" in value or "\x00" in value:
        errors.append(f"{path} must be a normalized relative POSIX path")
        return
    parsed = PurePosixPath(value)
    if (
        parsed.is_absolute()
        or value != parsed.as_posix()
        or any(part in {"", ".", ".."} for part in parsed.parts)
    ):
        errors.append(f"{path} must be a normalized relative POSIX path")


def _string_list(
    value: Any,
    path: str,
    errors: list[str],
    *,
    nonempty: bool = True,
) -> list[str] | None:
    if not isinstance(value, list):
        errors.append(f"{path} must be an array")
        return None
    if nonempty and not value:
        errors.append(f"{path} must not be empty")
    if any(not isinstance(item, str) or not item for item in value):
        errors.append(f"{path} entries must be non-empty strings")
        return None
    if len(value) != len(set(value)):
        errors.append(f"{path} entries must be unique")
    return value


def _validate_file_bindings(
    value: Any,
    path: str,
    errors: list[str],
    *,
    nonempty: bool,
) -> list[Mapping[str, Any]] | None:
    if not isinstance(value, list):
        errors.append(f"{path} must be an array")
        return None
    if nonempty and not value:
        errors.append(f"{path} must not be empty")
    rows: list[Mapping[str, Any]] = []
    labels: list[str] = []
    paths: list[str] = []
    for index, item in enumerate(value):
        row = _exact_fields(item, FILE_BINDING_FIELDS, f"{path}[{index}]", errors)
        if row is None:
            continue
        _nonempty_string(row.get("label"), f"{path}[{index}].label", errors)
        _relative_path(row.get("path"), f"{path}[{index}].path", errors)
        if not _is_sha256(row.get("sha256")):
            errors.append(f"{path}[{index}].sha256 must be a lowercase SHA-256")
        if isinstance(row.get("label"), str):
            labels.append(row["label"])
        if isinstance(row.get("path"), str):
            paths.append(row["path"])
        rows.append(row)
    if len(labels) != len(set(labels)):
        errors.append(f"{path} labels must be unique")
    if len(paths) != len(set(paths)):
        errors.append(f"{path} paths must be unique")
    return rows


def _validate_run_contract(value: Any, path: str, errors: list[str]) -> None:
    contract = _exact_fields(value, RUN_CONTRACT_FIELDS, path, errors)
    if contract is None:
        return
    for field in (
        "scenario_count",
        "initial_cells",
        "compatibility_smoke_cells",
        "confirmation_max_cells",
        "retry_limit",
    ):
        if not _is_nonnegative_int(contract.get(field)):
            errors.append(f"{path}.{field} must be a non-negative integer")
    if contract.get("scenario_count") == 0:
        errors.append(f"{path}.scenario_count must be greater than zero")
    arms = _string_list(contract.get("arms"), f"{path}.arms", errors)
    immutable = _string_list(
        contract.get("immutable_fields"), f"{path}.immutable_fields", errors
    )
    forbidden = _string_list(
        contract.get("forbidden_substitutions"),
        f"{path}.forbidden_substitutions",
        errors,
    )
    if not _is_sha256(contract.get("decision_rule_sha256")):
        errors.append(f"{path}.decision_rule_sha256 must be a lowercase SHA-256")
    scenarios = contract.get("scenario_count")
    initial = contract.get("initial_cells")
    if _is_nonnegative_int(scenarios) and arms is not None and _is_nonnegative_int(initial):
        if initial != scenarios * len(arms):
            errors.append(
                f"{path}.initial_cells must equal scenario_count multiplied by arm count"
            )
    if immutable is not None:
        missing = sorted(REQUIRED_IMMUTABLE_FIELDS - set(immutable))
        if missing:
            errors.append(
                f"{path}.immutable_fields missing required value(s): {', '.join(missing)}"
            )
    if forbidden is not None:
        missing = sorted(REQUIRED_FORBIDDEN_SUBSTITUTIONS - set(forbidden))
        if missing:
            errors.append(
                f"{path}.forbidden_substitutions missing required value(s): {', '.join(missing)}"
            )


def validate_frozen_protocol_lock(value: Any) -> list[str]:
    errors: list[str] = []
    lock = _exact_fields(value, LOCK_FIELDS, "lock", errors)
    if lock is None:
        return errors
    if lock.get("schema_version") != LOCK_SCHEMA:
        errors.append(f"lock.schema_version must equal {LOCK_SCHEMA}")
    _nonempty_string(lock.get("protocol_id"), "lock.protocol_id", errors)
    governing = _exact_fields(
        lock.get("governing_prompt"),
        FILE_BINDING_FIELDS,
        "lock.governing_prompt",
        errors,
    )
    if governing is not None:
        if governing.get("label") != "governing-prompt":
            errors.append("lock.governing_prompt.label must equal governing-prompt")
        _relative_path(governing.get("path"), "lock.governing_prompt.path", errors)
        if not _is_sha256(governing.get("sha256")):
            errors.append("lock.governing_prompt.sha256 must be a lowercase SHA-256")
    bindings = _validate_file_bindings(
        lock.get("execution_bindings"),
        "lock.execution_bindings",
        errors,
        nonempty=True,
    )
    if bindings is not None:
        labels = {
            row.get("label") for row in bindings if isinstance(row.get("label"), str)
        }
        missing = sorted(REQUIRED_EXECUTION_LABELS - labels)
        if missing:
            errors.append(
                "lock.execution_bindings missing required label(s): "
                + ", ".join(missing)
            )
    _validate_run_contract(lock.get("run_contract"), "lock.run_contract", errors)
    _validate_file_bindings(
        lock.get("authoring_provenance"),
        "lock.authoring_provenance",
        errors,
        nonempty=False,
    )
    if not _is_sha256(lock.get("lock_sha256")):
        errors.append("lock.lock_sha256 must be a lowercase SHA-256")
    elif lock["lock_sha256"] != canonical_lock_sha256(lock):
        errors.append("lock.lock_sha256 does not match canonical payload")
    return errors


def validate_frozen_protocol_run(value: Any) -> list[str]:
    errors: list[str] = []
    run = _exact_fields(value, RUN_FIELDS, "run", errors)
    if run is None:
        return errors
    if run.get("schema_version") != RUN_SCHEMA:
        errors.append(f"run.schema_version must equal {RUN_SCHEMA}")
    _nonempty_string(run.get("protocol_id"), "run.protocol_id", errors)
    if not _is_sha256(run.get("lock_sha256")):
        errors.append("run.lock_sha256 must be a lowercase SHA-256")
    _validate_run_contract(run.get("run_contract"), "run.run_contract", errors)
    steering = _exact_fields(run.get("steering"), STEERING_FIELDS, "run.steering", errors)
    if steering is not None:
        classification = steering.get("classification")
        if classification not in STEERING_CLASSES:
            errors.append(
                "run.steering.classification must be continue, same-scope-repair, or replace-protocol"
            )
        if not _is_sha256(steering.get("instruction_sha256")):
            errors.append(
                "run.steering.instruction_sha256 must be a lowercase SHA-256"
            )
        changed = _string_list(
            steering.get("changed_locked_fields"),
            "run.steering.changed_locked_fields",
            errors,
            nonempty=False,
        )
        authorization = steering.get("replacement_authorization_sha256")
        if authorization is not None and not _is_sha256(authorization):
            errors.append(
                "run.steering.replacement_authorization_sha256 must be null or a lowercase SHA-256"
            )
        repair_class = steering.get("repair_class")
        if repair_class is not None and not isinstance(repair_class, str):
            errors.append("run.steering.repair_class must be null or a string")
        if classification == "continue":
            if changed:
                errors.append("continue steering cannot change locked fields")
            if authorization is not None:
                errors.append("continue steering cannot carry replacement authorization")
            if repair_class is not None:
                errors.append("continue steering cannot carry a repair class")
        elif classification == "same-scope-repair":
            if changed:
                errors.append("same-scope repair cannot change locked fields")
            if repair_class not in SAME_SCOPE_REPAIR_CLASSES:
                errors.append("same-scope repair has an unsupported repair class")
            if authorization is not None:
                errors.append(
                    "same-scope repair cannot carry replacement authorization"
                )
        elif classification == "replace-protocol":
            if not changed:
                errors.append("replace-protocol steering must identify changed locked fields")
            if authorization is None:
                errors.append(
                    "replace-protocol steering must carry replacement authorization"
                )
            if repair_class is not None:
                errors.append("replace-protocol steering cannot carry a repair class")
    return errors


def _resolved_binding(base_dir: Path, relative: str) -> tuple[Path | None, str | None]:
    path_errors: list[str] = []
    _relative_path(relative, "binding.path", path_errors)
    if path_errors:
        return None, "invalid-path"
    base = base_dir.resolve()
    candidate = base / Path(*PurePosixPath(relative).parts)
    current = base
    for part in PurePosixPath(relative).parts:
        current = current / part
        try:
            if current.is_symlink():
                return None, "symlink"
        except OSError:
            return None, "unreadable"
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError):
        return None, "unreadable"
    try:
        resolved.relative_to(base)
    except ValueError:
        return None, "outside-base"
    try:
        is_file = candidate.is_file()
    except OSError:
        return None, "unreadable"
    if not is_file:
        return None, "missing"
    return candidate, None


def evaluate_frozen_protocol(
    lock_value: Any,
    run_value: Any,
    *,
    base_dir: Path,
) -> dict[str, Any]:
    """Evaluate an exact run against a sealed protocol and live bindings."""

    lock_errors = validate_frozen_protocol_lock(lock_value)
    run_errors = validate_frozen_protocol_run(run_value)
    reasons = [*lock_errors, *run_errors]
    checks: dict[str, bool] = {
        "lock_structure": not lock_errors,
        "run_structure": not run_errors,
    }
    live_bindings: dict[str, dict[str, Any]] = {}
    provenance_labels: list[str] = []
    if not isinstance(lock_value, Mapping) or not isinstance(run_value, Mapping):
        return {
            "schema_version": "cwo-frozen-protocol-evaluation:v1",
            "decision": PROTOCOL_BLOCKED,
            "checks": checks,
            "reasons": reasons,
            "live_execution_bindings": live_bindings,
            "authoring_provenance": {
                "live_gated": False,
                "recorded_labels": provenance_labels,
            },
        }

    protocol_match = lock_value.get("protocol_id") == run_value.get("protocol_id")
    lock_match = lock_value.get("lock_sha256") == run_value.get("lock_sha256")
    contract_match = lock_value.get("run_contract") == run_value.get("run_contract")
    checks.update(
        {
            "protocol_id": protocol_match,
            "lock_binding": lock_match,
            "run_contract": contract_match,
        }
    )
    if not protocol_match:
        reasons.append("run protocol_id does not match frozen lock")
    if not lock_match:
        reasons.append("run lock_sha256 does not match frozen lock")
    if not contract_match:
        reasons.append("run contract differs from frozen protocol")

    bindings: list[Mapping[str, Any]] = []
    governing = lock_value.get("governing_prompt")
    if isinstance(governing, Mapping):
        bindings.append(governing)
    execution = lock_value.get("execution_bindings")
    if isinstance(execution, list):
        bindings.extend(row for row in execution if isinstance(row, Mapping))
    all_live = True
    for row in bindings:
        label = row.get("label")
        relative = row.get("path")
        expected = row.get("sha256")
        if not isinstance(label, str) or not isinstance(relative, str):
            all_live = False
            continue
        path, path_error = _resolved_binding(base_dir, relative)
        actual = file_sha256(path) if path is not None else None
        passed = path_error is None and actual == expected
        live_bindings[label] = {
            "path": relative,
            "expected_sha256": expected,
            "actual_sha256": actual,
            "path_error": path_error,
            "passed": passed,
        }
        if not passed:
            all_live = False
            reasons.append(f"execution-binding-drift:{label}")
    checks["live_execution_bindings"] = all_live and bool(bindings)

    provenance = lock_value.get("authoring_provenance")
    if isinstance(provenance, list):
        provenance_labels = [
            str(row.get("label"))
            for row in provenance
            if isinstance(row, Mapping) and isinstance(row.get("label"), str)
        ]

    steering = run_value.get("steering")
    classification = (
        steering.get("classification") if isinstance(steering, Mapping) else None
    )
    changed = (
        steering.get("changed_locked_fields")
        if isinstance(steering, Mapping)
        else None
    )
    unchanged = isinstance(changed, list) and not changed
    checks["steering_preserves_lock"] = (
        classification in {"continue", "same-scope-repair"} and unchanged
    )

    if classification == "replace-protocol":
        authorization = steering.get("replacement_authorization_sha256")
        if authorization is not None and not lock_errors and not run_errors:
            reasons.append("authorized-replacement-requires-new-protocol-lock")
            decision = NEW_PROTOCOL_REQUIRED
        else:
            reasons.append("replacement-authorization-missing")
            decision = PROTOCOL_BLOCKED
    elif reasons or not all(checks.values()):
        decision = PROTOCOL_BLOCKED
    else:
        decision = PROTOCOL_READY

    return {
        "schema_version": "cwo-frozen-protocol-evaluation:v1",
        "protocol_id": lock_value.get("protocol_id"),
        "lock_sha256": lock_value.get("lock_sha256"),
        "decision": decision,
        "checks": checks,
        "reasons": sorted(set(reasons)),
        "live_execution_bindings": live_bindings,
        "authoring_provenance": {
            "live_gated": False,
            "recorded_labels": provenance_labels,
        },
    }


def inspect_python_cache_drift(root: Path) -> dict[str, Any]:
    """Classify bytecode drift without reading protected source file content."""

    supplied_root = root
    root = root.resolve(strict=False)
    repairable_files: list[str] = []
    repairable_directories: list[str] = []
    suspicious_paths: list[str] = []
    stray_pyc: list[str] = []
    if not root.is_dir() or supplied_root.is_symlink():
        return {
            "root": str(root),
            "status": "suspicious-derived-cache",
            "repairable_files": [],
            "repairable_directories": [],
            "suspicious_paths": [str(root)],
        }

    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(directory)
        for dirname in tuple(dirnames):
            candidate = current / dirname
            if dirname == "__pycache__" and candidate.is_symlink():
                suspicious_paths.append(str(candidate.relative_to(root)))
        for filename in filenames:
            path = current / filename
            if path.suffix == ".pyc" and current.name != "__pycache__":
                stray_pyc.append(str(path.relative_to(root)))
        if current.name != "__pycache__":
            continue
        relative_dir = str(current.relative_to(root))
        try:
            directory_mode = current.lstat().st_mode
        except OSError:
            suspicious_paths.append(relative_dir)
            continue
        if not stat.S_ISDIR(directory_mode) or current.is_symlink():
            suspicious_paths.append(relative_dir)
            continue
        if dirnames:
            suspicious_paths.extend(
                str((current / name).relative_to(root)) for name in sorted(dirnames)
            )
        for filename in sorted(filenames):
            path = current / filename
            relative = str(path.relative_to(root))
            try:
                mode = path.lstat().st_mode
            except OSError:
                suspicious_paths.append(relative)
                continue
            if stat.S_ISREG(mode) and not path.is_symlink() and path.suffix == ".pyc":
                repairable_files.append(relative)
            else:
                suspicious_paths.append(relative)
        repairable_directories.append(relative_dir)

    suspicious_paths.extend(stray_pyc)
    if suspicious_paths:
        status = "suspicious-derived-cache"
    elif repairable_files or repairable_directories:
        status = "repairable-derived-cache"
    else:
        status = "clean"
    return {
        "root": str(root),
        "status": status,
        "repairable_files": sorted(set(repairable_files)),
        "repairable_directories": sorted(
            set(repairable_directories), key=lambda item: (-item.count("/"), item)
        ),
        "suspicious_paths": sorted(set(suspicious_paths)),
    }


def repair_python_cache_drift(root: Path) -> dict[str, Any]:
    """Remove only cache paths that :func:`inspect_python_cache_drift` accepts."""

    before = inspect_python_cache_drift(root)
    if before["status"] == "suspicious-derived-cache":
        return {
            "status": "repair-blocked",
            "before": before,
            "removed_files": [],
            "removed_directories": [],
            "after": before,
        }
    resolved_root = Path(before["root"])
    # Repeat path-type checks before the first mutation.  This does not make a
    # hostile shared filesystem atomic, but it prevents a changed or replaced
    # cache entry from being accepted on stale inspection evidence.
    for relative in before["repairable_files"]:
        path = resolved_root / relative
        try:
            mode = path.lstat().st_mode
        except OSError:
            return {
                "status": "repair-blocked",
                "before": before,
                "removed_files": [],
                "removed_directories": [],
                "after": inspect_python_cache_drift(resolved_root),
            }
        if (
            not stat.S_ISREG(mode)
            or path.is_symlink()
            or path.suffix != ".pyc"
            or path.parent.name != "__pycache__"
        ):
            return {
                "status": "repair-blocked",
                "before": before,
                "removed_files": [],
                "removed_directories": [],
                "after": inspect_python_cache_drift(resolved_root),
            }
    for relative in before["repairable_directories"]:
        path = resolved_root / relative
        try:
            mode = path.lstat().st_mode
        except OSError:
            return {
                "status": "repair-blocked",
                "before": before,
                "removed_files": [],
                "removed_directories": [],
                "after": inspect_python_cache_drift(resolved_root),
            }
        if not stat.S_ISDIR(mode) or path.is_symlink() or path.name != "__pycache__":
            return {
                "status": "repair-blocked",
                "before": before,
                "removed_files": [],
                "removed_directories": [],
                "after": inspect_python_cache_drift(resolved_root),
            }
    removed_files: list[str] = []
    removed_directories: list[str] = []
    for relative in before["repairable_files"]:
        path = resolved_root / relative
        path.unlink()
        removed_files.append(relative)
    for relative in before["repairable_directories"]:
        path = resolved_root / relative
        path.rmdir()
        removed_directories.append(relative)
    after = inspect_python_cache_drift(resolved_root)
    return {
        "status": "repaired" if before["status"] != "clean" else "clean",
        "before": before,
        "removed_files": removed_files,
        "removed_directories": removed_directories,
        "after": after,
    }
