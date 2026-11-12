"""Source-checkout fixture; external qualified offline execution is required."""

import argparse
import hashlib
import json
import os
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


BINARY_SIZE = 308139304
BINARY_SHA256 = (
    "b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306"
)
OUTPUT_LIMIT = 65536
TIMEOUT_SECONDS = 15
SCOPE = (
    "Fixed offline startup-config loader fixture only; external ROOT-qualified C "
    "execution remains required. No AppServer loop/RPC/thread/turn/model/study "
    "or OS qualification; reports confer no execution or admission authority."
)
CATALOG = (
    '[permissions.cwo-offline-deny.filesystem]\n'
    '"/" = "deny"\n'
    '[permissions.cwo-offline-deny.network]\n'
    "enabled = false\n"
)


@dataclass(frozen=True)
class Case:
    name: str
    config: str
    detail: str = ""


CASES = (
    Case("known-builtin", 'default_permissions = ":read-only"\n'),
    Case("named-root-deny", 'default_permissions = "cwo-offline-deny"\n' + CATALOG),
    Case(
        "unknown-named-with-valid-catalog",
        'default_permissions = "cwo-unknown-name"\n' + CATALOG,
        "default_permissions refers to undefined profile `cwo-unknown-name`",
    ),
    Case(
        "missing-default-with-valid-catalog",
        CATALOG,
        "config defines `[permissions]` profiles but does not set `default_permissions`",
    ),
    Case(
        "undefined-parent",
        'default_permissions = "cwo-offline-deny"\n'
        '[permissions.cwo-offline-deny]\n'
        'extends = "cwo-missing-parent"\n',
        "permissions profile `cwo-offline-deny` extends undefined profile `cwo-missing-parent`",
    ),
    Case(
        "cycle-parent",
        'default_permissions = "cwo-offline-deny"\n'
        '[permissions.cwo-offline-deny]\n'
        'extends = "cwo-second"\n'
        '[permissions.cwo-second]\n'
        'extends = "cwo-offline-deny"\n',
        "permissions profile inheritance cycle detected: "
        "cwo-offline-deny -> cwo-second -> cwo-offline-deny",
    ),
    Case(
        "strict-unknown-field",
        'default_permissions = ":read-only"\n'
        "this_is_not_a_known_config_field = true\n",
        "unknown configuration field `this_is_not_a_known_config_field`",
    ),
)


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _identity(info):
    return {
        "size": info.st_size,
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": info.st_mode,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
    }


def _fingerprint(path, size):
    initial = path.lstat()
    _require(stat.S_ISREG(initial.st_mode), "not a regular file (symlinks refused)")
    _require(initial.st_size == size, "unexpected file size")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        opened = _identity(os.fstat(stream.fileno()))
        _require(opened == _identity(initial), "file changed before hashing")
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        _require(_identity(os.fstat(stream.fileno())) == opened, "file changed while hashing")
    _require(_identity(path.lstat()) == opened, "file changed after hashing")
    return {**opened, "sha256": digest.hexdigest()}


def _command(binary):
    return [
        str(binary), "-m", "gpt-6.1-sol",
        "-c", 'service_tier="default"',
        "-c", 'model_reasoning_effort="high"',
        "app-server", "--strict-config", "--print-startup-config",
    ]


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("non-JSON constant: " + value)


def _keys(value, keys, label):
    _require(type(value) is dict, label + " must be an object")
    _require(set(value) == set(keys), label + " has unexpected or missing fields")


def _integer(value, expected, label):
    _require(type(value) is int and value == expected, label + " is not the expected integer")


def _healthy(payload):
    _keys(payload, ("appServerVersion", "configRequirements"), "success")
    _require(payload["appServerVersion"] == "0.164.0", "wrong appServerVersion")
    requirements = payload["configRequirements"]
    _keys(requirements, ("supportsIndependentSpeedModes", "requirements"), "configRequirements")
    _require(requirements["supportsIndependentSpeedModes"] is True, "wrong speed-mode primitive")
    _require(requirements["requirements"] is None, "unexpected requirements")


def _refusal(case, payload, config):
    _keys(payload, ("error",), "failure")
    error = payload["error"]
    _keys(error, ("code", "data", "message"), "error")
    _integer(error["code"], -32600, "error.code")
    data = error["data"]
    _keys(data, ("reason", "filePath", "line", "column", "detail"), "error.data")
    _require(data["reason"] == "configLoad", "wrong error reason")
    detail = case.detail
    if case.name == "strict-unknown-field":
        _require(data["filePath"] == str(config), "wrong diagnostic filePath")
        _integer(data["line"], 2, "error.data.line")
        _integer(data["column"], 1, "error.data.column")
        detail = f"{config}:2:1: {detail}"
    else:
        _require(
            all(data[key] is None for key in ("filePath", "line", "column")),
            "unexpected diagnostic location",
        )
    _require(type(data["detail"]) is str and data["detail"] == detail, "wrong case diagnostic")
    _require(error["message"] == "failed to load configuration: " + detail, "wrong error message")


def _classify(case, result, config):
    _require(type(result.returncode) is int, "returncode must be an integer")
    for output in (result.stdout, result.stderr):
        _require(type(output) is bytes, "captured output must be bytes")
        _require(len(output) <= OUTPUT_LIMIT, "captured output exceeds diagnostic limit")
    stdout = result.stdout.decode("utf-8")
    stderr = result.stderr.decode("utf-8")
    payload = json.loads(
        stdout, object_pairs_hook=_unique_object, parse_constant=_reject_constant
    )
    if not case.detail:
        _integer(result.returncode, 0, "returncode")
        _require(stderr == "", "unexpected stderr")
        _healthy(payload)
        return "healthy"
    _integer(result.returncode, 1, "returncode")
    _require(stderr == "Error: startup configuration unavailable\n", "unexpected stderr")
    _refusal(case, payload, config)
    return "expected-config-refusal"


def _capture(raw):
    if type(raw) is not bytes:
        return {"unexpected_type": type(raw).__name__}
    return {
        "text": raw[:OUTPUT_LIMIT].decode("utf-8", errors="backslashreplace"),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "truncated": len(raw) > OUTPUT_LIMIT,
    }


def _kind(mode):
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "file"
    return "special"


def _inventory(root):
    entries, pending = [], [root]
    while pending:
        for path in sorted(pending.pop().iterdir()):
            if len(entries) == 256:
                return {"entries": entries, "truncated": True}
            info = path.lstat()
            kind = _kind(info.st_mode)
            entries.append({"path": str(path.relative_to(root)), "kind": kind})
            if kind == "directory":
                pending.append(path)
    return {"entries": entries, "truncated": False}


def _observe_private(record, root, config, configuration):
    record["private_after"] = _inventory(root)
    record["config_after"] = _fingerprint(config, len(configuration))
    _require(not record["private_after"]["truncated"], "private inventory exceeded limit")
    _require(
        record["config_after"]["sha256"] == record["config_sha256"],
        "fixture configuration changed during execution",
    )


def _execute_case(case, runner, command, config, cwd, env, record):
    try:
        result = runner(
            command, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL,
            capture_output=True, shell=False, timeout=TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        record["stdout"] = _capture(exc.stdout or b"")
        record["stderr"] = _capture(exc.stderr or b"")
        record["issues"].append("subprocess timeout")
        return
    except OSError as exc:
        record["issues"].append("subprocess OSError: " + str(exc)[:2000])
        return
    record["returncode"] = result.returncode
    record["stdout"] = _capture(result.stdout)
    record["stderr"] = _capture(result.stderr)
    try:
        record["classification"] = _classify(case, result, config)
    except (ValueError, TypeError, RecursionError) as exc:
        record["issues"].append("invalid result: " + str(exc)[:2000])


def _run_case(binary, case, runner):
    configuration = case.config.encode("utf-8")
    record = {
        "name": case.name, "config": case.config,
        "config_sha256": hashlib.sha256(configuration).hexdigest(),
        "command": _command(binary), "returncode": None,
        "stdout": _capture(b""), "stderr": _capture(b""),
        "classification": "unexpected", "issues": [],
    }
    collected = False
    try:
        with tempfile.TemporaryDirectory(dir=Path.home(), prefix="w14-startup-fixture-") as name:
            root = Path(name)
            home, cwd = root / "home", root / "work"
            home.mkdir()
            cwd.mkdir()
            config = home / "config.toml"
            config.write_bytes(configuration)
            env = {"HOME": str(home), "CODEX_HOME": str(home), "PATH": "/usr/bin:/bin", "LC_ALL": "C"}
            record.update({"fixture_root": str(root), "config_path": str(config), "env": env, "cwd": str(cwd)})
            _execute_case(case, runner, record["command"], config, cwd, env, record)
            try:
                _observe_private(record, root, config, configuration)
            except (OSError, ValueError) as exc:
                record["issues"].append("private observation failed: " + str(exc)[:2000])
            collected = True
    except OSError as exc:
        if not collected:
            raise
        record["issues"].append("fixture cleanup failed: " + str(exc)[:2000])
    record["passed"] = not record["issues"]
    return record


def _check_after(report, binary):
    try:
        report["binary_after"] = _fingerprint(binary, BINARY_SIZE)
        _require(report["binary_after"] == report["binary_before"], "binary changed during fixture")
    except (OSError, ValueError) as exc:
        report["issues"].append("binary after-check failed: " + str(exc)[:2000])


def run_fixture(binary, runner=None):
    """Run only the fixed seven cases; injection is for fake unit tests."""
    binary = Path(os.path.abspath(binary))
    report = {
        "scope": SCOPE, "binary": str(binary), "command": _command(binary),
        "expected_binary_size": BINARY_SIZE, "expected_binary_sha256": BINARY_SHA256,
        "binary_before": None, "binary_after": None,
        "case_count": len(CASES), "cases": [], "issues": [], "passed": False,
        "completed_case_count": 0, "passed_case_count": 0,
    }
    try:
        report["binary_before"] = _fingerprint(binary, BINARY_SIZE)
        _require(report["binary_before"]["sha256"] == BINARY_SHA256, "binary SHA-256 mismatch")
    except (OSError, ValueError) as exc:
        report["issues"].append("binary preflight failed: " + str(exc)[:2000])
        return report
    try:
        for case in CASES:
            report["cases"].append(_run_case(binary, case, runner or subprocess.run))
    except (OSError, ValueError) as exc:
        report["issues"].append("fixture preparation/cleanup failed: " + str(exc)[:2000])
    finally:
        _check_after(report, binary)
    report["completed_case_count"] = len(report["cases"])
    report["passed_case_count"] = sum(case["passed"] for case in report["cases"])
    report["passed"] = (
        not report["issues"]
        and report["completed_case_count"] == len(CASES)
        and report["passed_case_count"] == len(CASES)
    )
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="explicit pinned Linux musl binary")
    parser.add_argument("--json", action="store_true", help="emit the bounded evidence report as JSON")
    args = parser.parse_args(argv)
    report = run_fixture(args.binary)
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print("Protocol startup-config fixture: " + ("PASS" if report["passed"] else "FAIL"))
        for case in report["cases"]:
            print(f'{case["name"]}: {case["classification"]}; issues={case["issues"]}')
        print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
