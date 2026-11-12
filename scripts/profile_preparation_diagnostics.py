"""Offline fake preparation checks; no runtime, policy compiler or grant authority."""

from __future__ import annotations

import json
import sys

MAX_BYTES = 32768
MAX_NODES = 2048
MAX_DEPTH = 12
MAX_CONTAINER = 128
MAX_STRING = 4096
VERSION = "0.164.0"
EXECUTABLE_SHA256 = "b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306"
THREAD_FIELDS = ("permissions", "sandbox", "approvalPolicy", "approvalsReviewer", "cwd", "ephemeral")
COMMAND_FIELDS = (
    "itemId", "threadId", "turnId", "startedAtMs", "approvalId", "kind",
    "command", "cwd", "environmentId", "reason", "additionalPermissions", "availableDecisions",
)


class Refusal(ValueError):
    def __init__(self, code, path):
        super().__init__(code)
        self.code, self.path = code, path


def _need(condition, code, path):
    if not condition:
        raise Refusal(code, path)


def _bounded(value):
    stack, nodes = [(value, 0)], 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        _need(nodes <= MAX_NODES and depth <= MAX_DEPTH, "input-limit", "$")
        kind = type(node)
        if kind is str:
            _need(len(node) <= MAX_STRING, "string-limit", "$")
            try:
                node.encode("utf-8")
            except UnicodeError:
                raise Refusal("invalid-unicode", "$") from None
        elif kind in (dict, list):
            _need(len(node) <= MAX_CONTAINER, "container-limit", "$")
            if kind is dict:
                _need(all(type(key) is str for key in node), "non-string-key", "$")
                stack.extend((key, depth + 1) for key in node)
                stack.extend((child, depth + 1) for child in node.values())
            else:
                stack.extend((child, depth + 1) for child in node)
        elif kind is int:
            _need(-(2**63) <= node < 2**63, "integer-limit", "$")
        else:
            _need(node is None or kind is bool, "unsupported-value-type", "$")


def _object(value, path, fields, required=()):
    _need(type(value) is dict, "object-required", path)
    for key in value:
        _need(key in fields, "unsupported-field", f"{path}.{key}")
    for key in required:
        _need(key in value, "missing-field", f"{path}.{key}")


def _text(value, path, nonempty=False):
    _need(type(value) is str, "string-required", path)
    _need(not nonempty or bool(value.strip()), "nonempty-string-required", path)


def _enum(value, path, choices):
    _need(type(value) is str and value in choices, "unsupported-enum", path)


def _strings(value, path):
    _need(type(value) is list, "array-required", path)
    for index, item in enumerate(value):
        _text(item, f"{path}[{index}]", nonempty=True)


def _approval_policy(value, path):
    if value is None:
        return
    if type(value) is str:
        _enum(value, path, ("untrusted", "on-request", "never"))
        return
    _object(value, path, ("granular",), ("granular",))
    granular = value["granular"]
    required = ("mcp_elicitations", "rules", "sandbox_approval")
    _object(granular, path + ".granular", required + ("request_permissions", "skill_approval"), required)
    for key, flag in granular.items():
        _need(type(flag) is bool, "boolean-required", path + ".granular." + key)


def _thread(value):
    path = "$.thread_start"
    _need(type(value) is dict, "object-required", path)
    _need(not ("permissions" in value and ("sandbox" in value or "sandboxPolicy" in value)),
          "mixed-profile-legacy-sandbox", path)
    _object(value, path, THREAD_FIELDS)
    _need("permissions" in value and value["permissions"] is not None, "missing-profile-name", path + ".permissions")
    _text(value["permissions"], path + ".permissions", nonempty=True)
    if "approvalPolicy" in value:
        _approval_policy(value["approvalPolicy"], path + ".approvalPolicy")
    if value.get("approvalsReviewer") is not None:
        _enum(value["approvalsReviewer"], path + ".approvalsReviewer", ("user", "auto_review", "guardian_subagent"))
    if value.get("cwd") is not None:
        _text(value["cwd"], path + ".cwd")
    if value.get("ephemeral") is not None:
        _need(type(value["ephemeral"]) is bool, "boolean-required", path + ".ephemeral")


def _inventory(value, selected):
    path = "$.inventory"
    fields = ("available_profiles", "managed_allowed_profiles", "expected_policy_id", "observed_policy_id")
    _object(value, path, fields, fields)
    for key in fields[:2]:
        _strings(value[key], path + "." + key)
        _need(len(set(value[key])) == len(value[key]), "duplicate-profile-name", path + "." + key)
    for key in fields[2:]:
        _text(value[key], path + "." + key, nonempty=True)
    available, allowed = value["available_profiles"], value["managed_allowed_profiles"]
    _need(set(allowed) <= set(available), "effective-policy-inventory-drift", path)
    _need(value["expected_policy_id"] == value["observed_policy_id"], "effective-policy-inventory-drift", path)
    _need(selected in available, "unknown-profile-name", "$.thread_start.permissions")
    _need(selected in allowed, "profile-disallowed", "$.thread_start.permissions")


def _filesystem(value, path):
    _object(value, path, ("read", "write", "entries", "globScanMaxDepth"))
    for key in ("read", "write"):
        if value.get(key) is not None:
            _strings(value[key], path + "." + key)
    if value.get("globScanMaxDepth") is not None:
        depth = value["globScanMaxDepth"]
        _need(type(depth) is int and 1 <= depth <= 128, "bounded-scan-depth-required", path + ".globScanMaxDepth")
    if value.get("entries") is None:
        return
    entries = value["entries"]
    _need(type(entries) is list, "array-required", path + ".entries")
    for index, entry in enumerate(entries):
        here = f"{path}.entries[{index}]"
        _object(entry, here, ("access", "path"), ("access", "path"))
        _enum(entry["access"], here + ".access", ("read", "write", "deny"))
        target = entry["path"]
        _need(type(target) is dict, "object-required", here + ".path")
        if target.get("type") == "path":
            _object(target, here + ".path", ("type", "path"), ("type", "path"))
            _text(target["path"], here + ".path.path", nonempty=True)
        elif target.get("type") == "special":
            _object(target, here + ".path", ("type", "value"), ("type", "value"))
            _object(target["value"], here + ".path.value", ("kind",), ("kind",))
            _enum(target["value"]["kind"], here + ".path.value.kind", ("root",))
        else:
            raise Refusal("unsupported-path-variant", here + ".path")


def _profile(value, path):
    _object(value, path, ("fileSystem", "network"))
    if value.get("fileSystem") is not None:
        _filesystem(value["fileSystem"], path + ".fileSystem")
    if value.get("network") is not None:
        network = value["network"]
        _object(network, path + ".network", ("enabled",))
        if network.get("enabled") is not None:
            _need(type(network["enabled"]) is bool, "boolean-required", path + ".network.enabled")


def _command(value):
    path = "$.command_approval"
    _object(value, path, COMMAND_FIELDS, ("itemId", "threadId", "turnId", "startedAtMs"))
    for key in ("itemId", "threadId", "turnId"):
        _text(value[key], path + "." + key, nonempty=True)
    _need(type(value["startedAtMs"]) is int, "integer-required", path + ".startedAtMs")
    for key in ("approvalId", "command", "cwd", "environmentId", "reason"):
        if value.get(key) is not None:
            _text(value[key], path + "." + key)
    if "kind" in value:
        _enum(value["kind"], path + ".kind", ("command", "writeStdin"))
    if value.get("additionalPermissions") is not None:
        _profile(value["additionalPermissions"], path + ".additionalPermissions")
    if value.get("availableDecisions") is not None:
        _need(type(value["availableDecisions"]) is list, "array-required", path + ".availableDecisions")
        for index, decision in enumerate(value["availableDecisions"]):
            _enum(decision, f"{path}.availableDecisions[{index}]", ("accept", "acceptForSession", "decline", "cancel"))


def _strict_response(value, result):
    path = "$.permissions_response"
    _object(value, path, ("permissions", "scope", "strictAutoReview"), ("permissions",))
    permissions = value["permissions"]
    # This semantic fixture slice supports only empty/network grants.
    _object(permissions, path + ".permissions", ("network",))
    _profile(permissions, path + ".permissions")
    scope = value.get("scope", "turn")
    _enum(scope, path + ".scope", ("turn", "session"))
    strict = value.get("strictAutoReview")
    _need(strict is None or type(strict) is bool, "boolean-required", path + ".strictAutoReview")
    if strict is not True:
        return
    if scope == "session":
        result["strict_expectation"] = "invalid-session-scope-no-strict-latch"
        raise Refusal("strict-session-scope", path + ".scope")
    network = permissions.get("network") or {}
    result["strict_expectation"] = (
        "nonempty-turn-forces-Guardian-not-user-callback"
        if network.get("enabled") is True else "empty-turn-no-strict-latch"
    )


def _check(value, result):
    fields = ("fake", "schema_version", "bundle", "experimental_api", "inventory",
              "thread_start", "command_approval", "permissions_response")
    _object(value, "$", fields, ("schema_version", "bundle", "inventory", "thread_start"))
    _need(value.get("fake") is True, "explicit-fake-required", "$.fake")
    _need(value["schema_version"] == VERSION, "unsupported-schema-version", "$.schema_version")
    _enum(value["bundle"], "$.bundle", ("stable", "experimental"))
    _need(value["bundle"] == "experimental", "profile-requires-experimental-bundle", "$.bundle")
    _need(value.get("experimental_api") is True, "capability-opt-in-required", "$.experimental_api")
    _thread(value["thread_start"])
    _inventory(value["inventory"], value["thread_start"]["permissions"])
    if "command_approval" in value:
        _command(value["command_approval"])
    if "permissions_response" in value:
        _strict_response(value["permissions_response"], result)


def _result():
    return {
        "authorship_record": "UNEXECUTED",
        "status": "unsupported", "preparation_accepted": False,
        "qualified": False, "effect_authority": False,
        "schema_capture_version": VERSION, "schema_capture_executable_sha256": EXECUTABLE_SHA256,
        "schema_capture_source_revision": None,
        "inventory_evidence": "declared-fake-only",
        "strict_expectation": "not-requested",
        "strict_expectation_basis": "recorded-architecture; exact-0.163-source-not-supplied",
        "reason_authenticates_retry": False,
        "runtime_OS": "untested", "live": "untested", "diagnostics": [],
    }


def diagnose(value):
    """Check one fake preparation, never admitting or activating anything."""
    result = _result()
    try:
        _bounded(value)
        _check(value, result)
    except Refusal as exc:
        result["diagnostics"] = [{"code": exc.code, "path": exc.path}]
    else:
        result.update(status="fake-tested", preparation_accepted=True)
    return result


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, "duplicate-json-key", "$")
        result[key] = value
    return result


def _constant(_value):
    raise Refusal("nonfinite-json-number", "$")


def diagnose_json(raw):
    """Parse bounded UTF-8 JSON; malformed input produces the same refusal shape."""
    try:
        _need(type(raw) in (bytes, str), "json-bytes-or-string-required", "$")
        _need(len(raw) <= MAX_BYTES, "input-byte-limit", "$")
        encoded = raw.encode("utf-8") if type(raw) is str else raw
        _need(len(encoded) <= MAX_BYTES, "input-byte-limit", "$")
        value = json.loads(encoded.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        result = _result()
        result["diagnostics"] = [{"code": exc.code if isinstance(exc, Refusal) else "invalid-json-or-encoding",
                                  "path": "$"}]
        return result
    return diagnose(value)


def main():
    if sys.argv[1:]:
        result = _result()
        result["diagnostics"] = [{"code": "stdin-only-no-arguments", "path": "$"}]
    else:
        try:
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        except (OSError, ValueError):
            result = _result()
            result["diagnostics"] = [{"code": "stdin-unreadable", "path": "$"}]
        else:
            result = diagnose_json(raw)
    sys.stdout.write(json.dumps(result, ensure_ascii=True, allow_nan=False) + "\n")
    return 0 if result["preparation_accepted"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
