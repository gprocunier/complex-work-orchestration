"""Conservative offline route and ledger arithmetic; no effects are authorized."""
from __future__ import annotations

import hashlib
import importlib
import json
import math
import re
import sys

import prepare_route_feasibility as planner

ledger = importlib.import_module("cwo_core.invocation_ledger")
WRAPPER_TYPE = "cwo-experimental-route-ledger-preparation"
SCOPE_TYPE = "cwo-experimental-route-ledger-scope-v1"
MAX_BYTES, MAX_OUTPUT_BYTES = 4 * 1024 * 1024, 1024 * 1024
MAX_DEPTH, MAX_ENTRIES, MAX_NODES = 48, 100_000, 256
MAX_ATTEMPTS, MAX_BUDGETS = 1024, 64
MAX_INTEGER = 2**53 - 1
RESOURCES = planner.RESOURCES
CONTEXT_FIELDS = (
    "aggregate_id", "parent_id", "run_id", "purpose", "output", "acceptance",
    "task_contract", "policy_sha256", "estimator_version", "projection_policy",
    "bound_input_sha256",
)
FALSE_FIELDS = (
    "operative", "qualified", "effect_authority", "ledger_snapshot_authenticated",
    "external_completeness_authenticated", "actual_quota_known", "actual_provider_billing_known",
)


class InvalidInput(ValueError):
    """A bounded refusal of supplied preparation data."""


def _require(condition, reason):
    if not condition:
        raise InvalidInput(reason)


def _exact(value, fields, label):
    _require(type(value) is dict and set(value) == set(fields), label + ": fields differ")


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _same(left, right):
    return _encode(left) == _encode(right)


def _digest(value):
    return hashlib.sha256(_encode(value)).hexdigest()


def _copy(value, depth, budget):
    _require(depth <= MAX_DEPTH, "input nesting exceeds the preparation bound")
    budget[0] += 1
    _require(budget[0] <= MAX_ENTRIES, "input entries exceed the preparation bound")
    kind = type(value)
    if kind in (dict, list):
        _require(len(value) <= MAX_ENTRIES - budget[0], "input container exceeds the entry bound")
        if kind is dict:
            result = {}
            for key, child in value.items():
                _require(type(key) is str, "input keys must be exact strings")
                result[_copy(key, depth + 1, budget)] = _copy(child, depth + 1, budget)
            return result
        return [_copy(child, depth + 1, budget) for child in value]
    if kind is str:
        try:
            budget[1] += len(value.encode("utf-8"))
        except UnicodeError as exc:
            raise InvalidInput("input text is not valid UTF-8") from exc
        _require(budget[1] <= MAX_BYTES, "input text exceeds the byte bound")
    elif kind is int:
        _require(-MAX_INTEGER <= value <= MAX_INTEGER, "input integer exceeds the preparation bound")
    elif kind is float:
        _require(math.isfinite(value), "input numbers must be finite")
    else:
        _require(value is None or kind is bool, "input contains an unsupported value type")
    return value


def _snapshot(value):
    copied = _copy(value, 0, [0, 0])
    frozen = _encode(copied)
    _require(len(frozen) <= MAX_BYTES, "input exceeds the encoded byte bound")
    return copied, frozen


def scope_context(route):
    """Identify supplied route context; this does not authenticate its source."""
    return {field: route[field] for field in CONTEXT_FIELDS}


def scope_sha256(context):
    """Hash the documented context record without granting provenance."""
    return _digest({"scope_type": SCOPE_TYPE, "context": context})


def _bounded_records(payload):
    _exact(payload, ("type", "version", "route_input", "ledger_snapshot", "expected", "node_attempts"), "wrapper")
    _require(payload["type"] == WRAPPER_TYPE and type(payload["version"]) is int
             and payload["version"] == 1, "unsupported experimental wrapper")
    route, document = payload["route_input"], payload["ledger_snapshot"]
    _require(type(route) is dict and type(route.get("nodes")) is list
             and 0 < len(route["nodes"]) <= MAX_NODES, "route node count exceeds the preparation bound")
    _exact(document, ledger.LEDGER_FIELDS, "ledger snapshot")
    for field, bound in (("budgets", MAX_BUDGETS), ("attempts", MAX_ATTEMPTS)):
        _require(type(document[field]) is dict and len(document[field]) <= bound,
                 "ledger record count exceeds the preparation bound")


def _binding(payload, prepared):
    expected, document = payload["expected"], payload["ledger_snapshot"]
    _exact(expected, ("budget_id", "scope_sha256", "context", "limits"), "expected aggregate")
    identity = expected["budget_id"]
    _require(type(identity) is str and identity == prepared["aggregate_id"], "aggregate budget identity drift")
    budget = document["budgets"].get(identity)
    _require(budget is not None, "selected aggregate budget is missing")
    context = scope_context(payload["route_input"])
    _require(_same(expected["context"], context), "independently expected route context drift")
    digest = scope_sha256(context)
    _require(expected["scope_sha256"] == digest == budget["scope_sha256"], "aggregate scope drift")
    _exact(expected["limits"], RESOURCES, "expected dimensions")
    _require(_same(expected["limits"], budget["limits"]), "independently expected budget limits drift")
    for resource in RESOURCES:
        limit = prepared["limits"][resource]
        _require(limit is None or _same(limit, budget["limits"][resource]), "prepared aggregate limit drift")
    return budget


def _mapping(payload, prepared):
    mapping = payload["node_attempts"]
    _exact(mapping, (node["id"] for node in prepared["nodes"]), "node attempt mapping")
    seen = set()
    for attempt_id in mapping.values():
        _require(attempt_id is None or type(attempt_id) is str, "attempt mapping needs a string or null")
        if attempt_id is not None:
            _require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", attempt_id) is not None,
                     "attempt mapping identity is invalid")
            _require(attempt_id not in seen, "duplicate attempt mapping")
            seen.add(attempt_id)
    return mapping


def _lineage(node, attempt, mapping, attempts):
    kind = {"primary": "initial", "dependent": "successor"}.get(node["kind"], node["kind"])
    parent_id = None if node["lineage_parent"] is None else mapping[node["lineage_parent"]]
    _require(node["lineage_parent"] is None or parent_id is not None, "mapped child has an unstarted parent")
    _require(_same(attempt["lineage"], {"kind": kind, "parent_attempt_id": parent_id}), "attempt lineage drift")
    for dependency in node["depends_on"]:
        dependency_id = mapping[dependency]
        _require(dependency_id is not None and dependency_id in attempts, "mapped dependency is missing")
        parent = attempts[dependency_id]
        _require(parent["sequence"] < attempt["sequence"],
                 "dependency creation sequence drift")
        _require(parent["created_at"] <= attempt["created_at"], "dependency creation order drift")
        if kind == "sibling" and dependency == node["lineage_parent"]:
            continue
        _require(parent["state"] == "terminal" and parent["history"][-1]["at"] <= attempt["created_at"],
                 "following attempt lacks a completed ledger transition for its dependency")


def _match(node, attempt, route_node, budget_id, mapping, attempts):
    _require(attempt["budget_id"] == budget_id, "mapped attempt belongs to another budget")
    _require(attempt["request_id"] == node["id"], "mapped request identity drift")
    digest = hashlib.sha256(route_node["rendered_request"].encode("utf-8")).hexdigest()
    _require(attempt["request_sha256"] == digest, "mapped rendered request drift")
    for resource in RESOURCES:
        planned = node["amounts"][resource]
        _require(planned is None or _same(planned, attempt["amount"][resource]), "mapped reserved amount drift")
    _lineage(node, attempt, mapping, attempts)


def _usage_unknown(attempt):
    return attempt["observed_usage"] is None and (
        attempt["state"] in ("invocation-intent", "reconciliation-required")
        or attempt["outcome"] in ledger.CHARGED_OUTCOMES)


def _observe(payload, prepared, budget, mapping):
    attempts = payload["ledger_snapshot"]["attempts"]
    selected = {key: value for key, value in attempts.items() if value["budget_id"] == budget["budget_id"]}
    charges = {key: ledger.derived_charge(json.loads(_encode(value))) for key, value in selected.items()}
    source_nodes = {node["id"]: node for node in payload["route_input"]["nodes"]}
    rows, mapped = [], set()
    for node in prepared["nodes"]:
        attempt_id = mapping[node["id"]]
        actual = {resource: 0 for resource in RESOURCES}
        if attempt_id is not None:
            _require(attempt_id in attempts, "mapped attempt is missing")
            _match(node, attempts[attempt_id], source_nodes[node["id"]], budget["budget_id"], mapping, attempts)
            actual = charges[attempt_id]
            mapped.add(attempt_id)
        planned = node["amounts"]
        remaining = {key: None if planned[key] is None else max(0, planned[key] - actual[key])
                     for key in RESOURCES}
        rows.append({"node_id": node["id"], "attempt_id": attempt_id, "planned": dict(planned),
                     "actual_charged": dict(actual), "still_committed": remaining})
    unmapped = [{"attempt_id": key, "actual_charged": charges[key]} for key in sorted(selected) if key not in mapped]
    gap = bool(unmapped) or any(_usage_unknown(attempt) for attempt in selected.values())
    return rows, charges, unmapped, gap


def _totals(rows, charges, limits, gap, prepared):
    actual, remaining, combined, lower, checks = {}, {}, {}, {}, {}
    for key in RESOURCES:
        actual[key] = sum(charge[key] for charge in charges.values())
        values = [row["still_committed"][key] for row in rows]
        known = sum(value for value in values if value is not None)
        remaining[key] = None if None in values else known
        combined[key] = None if remaining[key] is None else actual[key] + remaining[key]
        lower[key] = actual[key] + known
        limit_unknown = prepared["limits"][key] is None
        checks[key] = ("exceeded" if lower[key] > limits[key] else
                       "unknown" if combined[key] is None or limit_unknown else "within")
    status = ("over-budget" if "exceeded" in checks.values() else
              "unassessable" if gap or prepared["status"] == "unassessable" or "unknown" in checks.values()
              else "within-declared-limits")
    return {"status": status, "actual_charged": actual, "still_committed": remaining,
            "conservative_total": combined, "conservative_lower_bound": lower, "checks": checks}


def _reconcile(payload):
    _bounded_records(payload)
    route_bytes, ledger_bytes = _encode(payload["route_input"]), _encode(payload["ledger_snapshot"])
    errors = ledger.validate_ledger(json.loads(ledger_bytes))
    _require(not errors, "full supplied ledger snapshot failed its existing validator")
    prepared = planner.prepare(json.loads(route_bytes))
    _require(prepared["status"] != "invalid", "original route input failed its existing planner")
    budget = _binding(payload, prepared)
    mapping = _mapping(payload, prepared)
    rows, charges, unmapped, gap = _observe(payload, prepared, budget, mapping)
    result = _totals(rows, charges, budget["limits"], gap, prepared)
    result.update(budget_id=budget["budget_id"], scope_sha256=budget["scope_sha256"],
                  route_input_sha256=prepared["bound_input_sha256"],
                  ledger_snapshot_sha256=hashlib.sha256(ledger_bytes).hexdigest(),
                  limits=dict(budget["limits"]), planned_totals=prepared["totals"],
                  nodes=rows, unmapped_attempts=unmapped, completeness_gap=gap,
                  reasons=[] if result["status"] == "within-declared-limits" else
                  ["Conservative arithmetic exceeds a limit or retains unresolved quantities or coverage."])
    return result


def _invalid():
    return {**dict.fromkeys(FALSE_FIELDS, False), "status": "invalid",
            "reasons": ["Supplied preparation data failed a bounded consistency check."]}


def prepare(payload):
    """Compute from copied input; unexpected producer failures retain their identity."""
    try:
        copied, frozen = _snapshot(payload)
        result = {**_reconcile(copied), **dict.fromkeys(FALSE_FIELDS, False),
                  "supplied_input_sha256": hashlib.sha256(frozen).hexdigest()}
        _require(len(_encode(result)) <= MAX_OUTPUT_BYTES, "diagnostic exceeds the output bound")
        return result
    except InvalidInput:
        return _invalid()


def _parse_integer(text):
    _require(len(text.lstrip("-")) <= 16, "JSON integer exceeds the preparation bound")
    value = int(text)
    _require(-MAX_INTEGER <= value <= MAX_INTEGER, "JSON integer exceeds the preparation bound")
    return value


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "JSON object repeats a textual key")
        result[key] = value
    return result


def _constant(_text):
    raise InvalidInput("JSON numbers must be finite")


def _scan(text):
    depth, entries, quoted, escaped, atom = 0, 0, False, False, False
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
            entries += 1
            atom = False
        elif char in "[{":
            depth += 1
            entries += 1
            atom = False
        elif char in "]}":
            depth -= 1
            atom = False
        elif char in ",: \t\r\n":
            atom = False
        elif not atom:
            entries += 1
            atom = True
        _require(depth <= MAX_DEPTH + 1 and entries <= MAX_ENTRIES, "JSON structure exceeds the preparation bound")


def _decode(raw):
    _require(type(raw) is bytes and len(raw) <= MAX_BYTES, "stdin exceeds the UTF-8 byte bound")
    try:
        text = raw.decode("utf-8")
        _scan(text)
        return json.loads(text, object_pairs_hook=_pairs, parse_int=_parse_integer, parse_constant=_constant)
    except (ValueError, OverflowError, RecursionError, UnicodeError) as exc:
        raise InvalidInput("stdin is not supported bounded JSON") from exc


def main(stdin=None, stdout=None):
    """Read one bounded object from stdin and print only its inert diagnostic."""
    stdin = sys.stdin.buffer if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    try:
        raw = stdin.read(MAX_BYTES + 1)
    except OSError:
        diagnostic = _invalid()
    else:
        try:
            payload = _decode(raw)
        except InvalidInput:
            diagnostic = _invalid()
        else:
            diagnostic = prepare(payload)
    stdout.write(_encode(diagnostic).decode("ascii") + "\n")
    return 0 if diagnostic["status"] == "within-declared-limits" else 2 if diagnostic["status"] == "invalid" else 1


if __name__ == "__main__":
    raise SystemExit(main())
