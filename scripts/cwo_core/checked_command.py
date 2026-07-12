from __future__ import annotations

import hashlib
import json
import os
import py_compile
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

SPEC_TYPE = "cwo-checked-command-spec"
RESULT_TYPE = "cwo-checked-command-result"
VERSION = 1
MODES = {"argv", "shell-source", "python-source"}
EXCLUDED_DIRS = {".git", ".beads", ".orchestration-audit", "__pycache__", ".pytest_cache"}


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _bytes_hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _strict_string(value: Any, path: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ValueError(f"{path} must be a string" + ("" if allow_empty else " with content"))
    return value


def _strict_bool(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{path} must be a boolean")
    return value


def _strict_int(value: Any, path: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{path} must be an integer >= {minimum}")
    return value


def _string_list(value: Any, path: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{path} must be a list")
    return [_strict_string(item, f"{path}[{index}]", allow_empty=True) for index, item in enumerate(value)]


def normalize_command_spec(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("spec must be a mapping")
    required = {
        "spec_type", "version", "command_id", "mode", "argv", "cwd", "env", "inherit_environment",
        "stdin", "source", "preflights", "mutation_intent", "allowed_paths", "timeout_seconds",
    }
    if set(value) != required:
        raise ValueError(f"spec must contain exact fields {sorted(required)}")
    if value["spec_type"] != SPEC_TYPE or value["version"] != VERSION:
        raise ValueError("unsupported checked-command spec type or version")
    command_id = _strict_string(value["command_id"], "command_id")
    mode = _strict_string(value["mode"], "mode")
    if mode not in MODES:
        raise ValueError(f"mode must be one of {sorted(MODES)}")
    argv = _string_list(value["argv"], "argv")
    cwd = Path(_strict_string(value["cwd"], "cwd")).expanduser().resolve()
    if not cwd.is_dir():
        raise ValueError("cwd must be an existing directory")
    if not isinstance(value["env"], Mapping):
        raise ValueError("env must be a mapping")
    env = {_strict_string(k, "env key"): _strict_string(v, f"env.{k}", allow_empty=True) for k, v in value["env"].items()}
    inherit_environment = _strict_bool(value["inherit_environment"], "inherit_environment")
    stdin = value["stdin"]
    if stdin is not None:
        stdin = _strict_string(stdin, "stdin", allow_empty=True)
    source = value["source"]
    if mode == "argv":
        if source is not None:
            raise ValueError("argv mode requires source=null")
        if not argv:
            raise ValueError("argv mode requires at least one argv item")
    else:
        source = _strict_string(source, "source", allow_empty=True)
    if not isinstance(value["preflights"], list):
        raise ValueError("preflights must be a list")
    preflights: list[dict[str, str]] = []
    for index, item in enumerate(value["preflights"]):
        if not isinstance(item, Mapping) or set(item) != {"kind", "value"}:
            raise ValueError(f"preflights[{index}] must contain kind and value")
        kind = _strict_string(item["kind"], f"preflights[{index}].kind")
        if kind not in {"json", "json-policy", "regex"}:
            raise ValueError(f"unsupported preflight kind {kind}")
        preflights.append({"kind": kind, "value": _strict_string(item["value"], f"preflights[{index}].value", allow_empty=True)})
    mutation_intent = _strict_string(value["mutation_intent"], "mutation_intent")
    if mutation_intent not in {"none", "workspace-scoped"}:
        raise ValueError("mutation_intent must be none or workspace-scoped")
    allowed_paths = _string_list(value["allowed_paths"], "allowed_paths")
    if mutation_intent == "workspace-scoped" and not allowed_paths:
        raise ValueError("workspace-scoped mutation requires allowed_paths")
    normalized_paths: list[str] = []
    for raw_path in allowed_paths:
        candidate = (cwd / raw_path).resolve() if not Path(raw_path).is_absolute() else Path(raw_path).resolve()
        try:
            relative = candidate.relative_to(cwd)
        except ValueError as exc:
            raise ValueError(f"allowed path escapes cwd: {raw_path}") from exc
        normalized_paths.append(relative.as_posix())
    timeout_seconds = _strict_int(value["timeout_seconds"], "timeout_seconds", 1)
    return {
        "spec_type": SPEC_TYPE, "version": VERSION, "command_id": command_id, "mode": mode,
        "argv": argv, "cwd": str(cwd), "env": env, "inherit_environment": inherit_environment,
        "stdin": stdin, "source": source, "preflights": preflights, "mutation_intent": mutation_intent,
        "allowed_paths": normalized_paths, "timeout_seconds": timeout_seconds,
    }


def classify_command_complexity(spec: Any) -> dict[str, Any]:
    normalized = normalize_command_spec(spec)
    reasons: list[str] = []
    argv = normalized["argv"]
    if normalized["mode"] != "argv":
        reasons.append("typed-source")
    if len(argv) >= 2 and Path(argv[0]).name.lower() in {"python", "python3", "bash", "sh"} and argv[1] == "-c":
        reasons.append("interpreter-inline-source")
    joined = " ".join(argv)
    if any(marker in joined for marker in ("|", ">", "<", "$(", "&&", "||", ";", "<<")):
        reasons.append("shell-metacharacters")
    quote_layers = joined.count("'") + joined.count('"')
    if quote_layers >= 4:
        reasons.append("nested-quotes")
    if normalized["preflights"]:
        reasons.append("nested-language")
    if normalized["env"]:
        reasons.append("explicit-environment")
    if normalized["mutation_intent"] != "none":
        reasons.append("mutation-command")
    return {"score": min(3, len(set(reasons))), "reasons": sorted(set(reasons)), "checked_execution_required": bool(reasons)}


def _snapshot(root: Path) -> dict[str, tuple[int, int]]:
    result: dict[str, tuple[int, int]] = {}
    for current, dirs, files in os.walk(root):
        dirs[:] = [item for item in dirs if item not in EXCLUDED_DIRS]
        base = Path(current)
        for name in files:
            path = base / name
            try:
                stat = path.stat()
            except OSError:
                continue
            result[path.relative_to(root).as_posix()] = (stat.st_size, stat.st_mtime_ns)
    return result


def _changed(before: Mapping[str, tuple[int, int]], after: Mapping[str, tuple[int, int]]) -> list[str]:
    return sorted(key for key in set(before) | set(after) if before.get(key) != after.get(key))


def _path_allowed(path: str, allowed: list[str]) -> bool:
    candidate = Path(path)
    return any(candidate == Path(root) or Path(root) in candidate.parents for root in allowed)


def _redact(text: str, secrets: list[str]) -> str:
    result = text
    for secret in secrets:
        if secret:
            result = result.replace(secret, "[REDACTED]")
    return result[:4096]


def _base_result(spec: dict[str, Any], complexity: dict[str, Any]) -> dict[str, Any]:
    return {
        "result_type": RESULT_TYPE, "version": VERSION, "command_id": spec["command_id"],
        "spec_sha256": _canonical_hash(spec), "mode": spec["mode"], "complexity": complexity,
        "preflight_status": "not-run", "linter": None, "execution_status": "not-started", "exit_code": None,
        "linted_sha256": None, "executed_sha256": None, "hash_match": None,
        "execution_started": False, "mutation_started": False, "mutated_paths": [],
        "failure_class": None, "quarantine_required": False,
        "diagnostics": {"stdout": "", "stderr": ""},
        "quoting_error_prevented": False, "avoided_retry_cycles": 0,
    }


def execute_checked_command(value: Any) -> dict[str, Any]:
    try:
        spec = normalize_command_spec(value)
    except ValueError as exc:
        result = {
            "result_type": RESULT_TYPE, "version": VERSION, "command_id": str(value.get("command_id", "invalid")) if isinstance(value, Mapping) else "invalid",
            "spec_sha256": _canonical_hash(value) if isinstance(value, Mapping) else _canonical_hash({"invalid": True}),
            "mode": str(value.get("mode", "invalid")) if isinstance(value, Mapping) else "invalid",
            "complexity": {"score": 0, "reasons": [], "checked_execution_required": True},
            "preflight_status": "failed", "linter": "spec-validator", "execution_status": "not-started", "exit_code": None,
            "linted_sha256": None, "executed_sha256": None, "hash_match": None, "execution_started": False,
            "mutation_started": False, "mutated_paths": [], "failure_class": "command-construction-failed",
            "quarantine_required": False, "diagnostics": {"stdout": "", "stderr": str(exc)[:4096]},
            "quoting_error_prevented": True, "avoided_retry_cycles": 1,
        }
        return result
    complexity = classify_command_complexity(spec)
    result = _base_result(spec, complexity)
    argv = spec["argv"]
    if spec["mode"] == "argv" and len(argv) >= 2 and Path(argv[0]).name.lower() in {"python", "python3", "bash", "sh"} and argv[1] == "-c":
        result.update({"preflight_status": "failed", "linter": "typed-source-policy", "failure_class": "typed-source-required", "quoting_error_prevented": True, "avoided_retry_cycles": 1})
        return result
    try:
        for preflight in spec["preflights"]:
            if preflight["kind"] in {"json", "json-policy"}:
                parsed = json.loads(preflight["value"])
                if preflight["kind"] == "json-policy" and not isinstance(parsed, Mapping):
                    raise ValueError("json-policy preflight requires an object")
            else:
                re.compile(preflight["value"])
    except (ValueError, json.JSONDecodeError, re.error) as exc:
        result.update({"preflight_status": "failed", "linter": "nested-language", "failure_class": "command-construction-failed", "diagnostics": {"stdout": "", "stderr": str(exc)[:4096]}, "quoting_error_prevented": True, "avoided_retry_cycles": 1})
        return result

    cwd = Path(spec["cwd"])
    environment = dict(os.environ) if spec["inherit_environment"] else {}
    environment.update(spec["env"])
    before = _snapshot(cwd)
    with tempfile.TemporaryDirectory(prefix="cwo-checked-command-") as temporary:
        temporary_root = Path(temporary)
        executable_argv: list[str]
        artifact: Path | None = None
        if spec["mode"] == "shell-source":
            artifact = temporary_root / "command.sh"
            source_bytes = spec["source"].encode("utf-8")
            artifact.write_bytes(source_bytes)
            result["linted_sha256"] = _bytes_hash(source_bytes)
            lint = subprocess.run([shutil.which("bash") or "/usr/bin/bash", "-n", str(artifact)], cwd=cwd, env=environment, text=True, capture_output=True, timeout=spec["timeout_seconds"], shell=False)
            result["linter"] = "bash -n"
            if lint.returncode != 0:
                result.update({"preflight_status": "failed", "failure_class": "command-construction-failed", "diagnostics": {"stdout": _redact(lint.stdout, list(spec["env"].values())), "stderr": _redact(lint.stderr, list(spec["env"].values()))}, "quoting_error_prevented": True, "avoided_retry_cycles": 1})
                return result
            executable_argv = [shutil.which("bash") or "/usr/bin/bash", str(artifact), *spec["argv"]]
        elif spec["mode"] == "python-source":
            artifact = temporary_root / "command.py"
            source_bytes = spec["source"].encode("utf-8")
            artifact.write_bytes(source_bytes)
            result["linted_sha256"] = _bytes_hash(source_bytes)
            result["linter"] = "py_compile"
            try:
                py_compile.compile(str(artifact), doraise=True)
            except py_compile.PyCompileError as exc:
                result.update({"preflight_status": "failed", "failure_class": "command-construction-failed", "diagnostics": {"stdout": "", "stderr": _redact(str(exc), list(spec["env"].values()))}, "quoting_error_prevented": True, "avoided_retry_cycles": 1})
                return result
            executable_argv = [sys.executable, str(artifact), *spec["argv"]]
        else:
            executable_argv = list(spec["argv"])
        result["preflight_status"] = "passed"
        if artifact is not None:
            result["executed_sha256"] = _bytes_hash(artifact.read_bytes())
            result["hash_match"] = result["linted_sha256"] == result["executed_sha256"]
            if not result["hash_match"]:
                result.update({"execution_status": "blocked", "failure_class": "checked-executed-hash-mismatch", "quarantine_required": True})
                return result
        else:
            result["hash_match"] = True
        try:
            result["execution_started"] = True
            completed = subprocess.run(executable_argv, cwd=cwd, env=environment, input=spec["stdin"], text=True, capture_output=True, timeout=spec["timeout_seconds"], shell=False)
            result["exit_code"] = completed.returncode
            result["execution_status"] = "passed" if completed.returncode == 0 else "failed"
            result["diagnostics"] = {"stdout": _redact(completed.stdout, list(spec["env"].values())), "stderr": _redact(completed.stderr, list(spec["env"].values()))}
            if completed.returncode != 0:
                result["failure_class"] = "execution-failed"
        except subprocess.TimeoutExpired as exc:
            result.update({"execution_status": "failed", "failure_class": "execution-timeout", "diagnostics": {"stdout": _redact(exc.stdout or "", list(spec["env"].values())), "stderr": _redact(exc.stderr or "", list(spec["env"].values()))}})
    after = _snapshot(cwd)
    mutated = _changed(before, after)
    result["mutated_paths"] = mutated
    result["mutation_started"] = bool(mutated)
    outside = [path for path in mutated if not _path_allowed(path, spec["allowed_paths"])]
    if spec["mutation_intent"] == "none" and mutated:
        outside = mutated
    if outside:
        result.update({"failure_class": "scope-violation", "quarantine_required": True, "execution_status": "quarantined"})
    return result
