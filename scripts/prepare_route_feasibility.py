"""Bounded offline arithmetic over declared route inputs; never invocation authority."""
from __future__ import annotations

import hashlib
import json
import math
import re
import sys

from cwo_core import work_sizing
from cwo_core.native_authority import AuthorityProvenanceError, canonical_authority_sha256

ESTIMATOR_VERSION = "route-preparation-v1/work-sizing-contracts-v1-v2"
MAX_BYTES = 2 * 1024 * 1024
MAX_NODES = 256
MAX_INTEGER = 2**53 - 1
RESOURCES = ("tool_calls", "runtime_seconds", "tokens", "cost_microunits")
NODE_FIELDS = {
    "id", "role", "depends_on", "kind", "lineage_parent", "execution",
    "prompt", "wrappers", "attachments", "sources", "rendered_request",
    "estimate_source", "source_sha256", "unit_estimate", "unit_sha256",
    "sizing_rationale", "uncertainty", "additional_input_tokens_upper",
}


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _exact(value, fields, label):
    _require(type(value) is dict and set(value) == set(fields),
             f"{label}: expected exactly {', '.join(sorted(fields))}")
    return value


def _text(value, label):
    _require(type(value) is str and bool(value.strip()), f"{label}: nonempty string required")
    return value


def _id(value, label):
    _text(value, label)
    _require(re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,95}", value) is not None,
             f"{label}: invalid string identity")
    return value


def _integer(value, label, minimum=0):
    _require(type(value) is int and minimum <= value <= MAX_INTEGER,
             f"{label}: integer in [{minimum}, {MAX_INTEGER}] required")
    return value


def _ids(value, label):
    _require(type(value) is list and len(value) <= MAX_NODES, f"{label}: bounded list required")
    result = [_id(item, label) for item in value]
    _require(len(set(result)) == len(result), f"{label}: duplicate identity")
    return result


def _tree(value):
    stack, count = [(value, 0)], 0
    while stack:
        item, depth = stack.pop()
        count += 1
        _require(depth <= 48 and count <= 100_000, "JSON structure exceeds preparation bounds")
        if type(item) is dict:
            _require(all(type(key) is str for key in item), "JSON keys must be strings")
            stack.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is int:
            _integer(item, "JSON integer", -MAX_INTEGER)
        elif type(item) is float:
            _require(math.isfinite(item), "JSON numbers must be finite")
        else:
            _require(item is None or type(item) in (str, bool), "JSON value type unsupported")
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    _require(len(encoded) <= MAX_BYTES, "JSON input exceeds byte bound")


def input_sha256(payload):
    """Identity only: callers must rebuild it after any input change."""
    _tree(payload)
    _require(type(payload) is dict, "input must be an object")
    return canonical_authority_sha256({key: value for key, value in payload.items()
                                       if key != "bound_input_sha256"})


def render_request(node):
    """The preparation format has exactly this deterministic UTF-8 rendering."""
    return json.dumps({key: node[key] for key in
                       ("execution", "prompt", "wrappers", "attachments", "sources")},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _measurement(text):
    _require(type(text) is str, "input component must be text")
    data = text.encode("utf-8")
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _graph_rows(rows, fields, label):
    _require(type(rows) is list and 0 < len(rows) <= MAX_NODES, f"{label}: bounded nonempty list required")
    result = {}
    for row in rows:
        _exact(row, fields, label)
        identity = _id(row["id"], f"{label}.id")
        _id(row["role"], f"{label}.role")
        _ids(row["depends_on"], f"{label}.depends_on")
        _require(identity not in result, f"{label}: duplicate identity")
        result[identity] = row
    return result


def _graph(payload):
    contract = _exact(payload["task_contract"], {"contract_id", "root_id", "required_roles"}, "task_contract")
    _id(contract["contract_id"], "contract_id")
    root = _id(contract["root_id"], "root_id")
    required = _graph_rows(contract["required_roles"], {"id", "role", "depends_on"},
                           "required_roles")
    nodes = _graph_rows(payload["nodes"], NODE_FIELDS, "nodes")
    _require(set(required) == set(nodes), "task contract role omission or undeclared node")
    _require(root in nodes, "task contract root is missing")
    for identity, node in nodes.items():
        _require(all(dependency in nodes for dependency in node["depends_on"]), "missing dependency node")
        _require(all(node[key] == required[identity][key] for key in ("role", "depends_on")),
                 "task contract role or dependency mismatch")
        if identity == root:
            _require(node["kind"] == "primary" and node["lineage_parent"] is None
                     and node["depends_on"] == [], "invalid primary lineage")
        else:
            _require(node["kind"] in ("dependent", "retry", "fallback", "sibling"), "invalid child kind")
            _id(node["lineage_parent"], "lineage_parent")
            _require(node["lineage_parent"] in node["depends_on"], "orphan lineage")
    remaining, ordered = set(nodes), []
    while remaining:
        ready = sorted(identity for identity in remaining
                       if not any(dependency in remaining for dependency in nodes[identity]["depends_on"]))
        _require(bool(ready), "dependency or lineage cycle")
        ordered.extend(nodes[identity] for identity in ready)
        remaining.difference_update(ready)
    return ordered


def _projection_policy(value):
    _exact(value, {"mode", "tokens_per_utf8_byte_upper", "input_overhead_tokens", "billing",
                   "rationale", "uncertainty"}, "projection_policy")
    _text(value["rationale"], "projection rationale")
    _text(value["uncertainty"], "projection uncertainty")
    _require(value["mode"] in ("unknown", "declared-conservative"), "unsupported projection mode")
    if value["mode"] == "unknown":
        _require(all(value[key] is None for key in
                     ("tokens_per_utf8_byte_upper", "input_overhead_tokens", "billing")),
                 "unknown projection must retain unknown quantities")
        return value
    _integer(value["tokens_per_utf8_byte_upper"], "tokens_per_utf8_byte_upper", 1)
    _integer(value["input_overhead_tokens"], "input_overhead_tokens")
    billing = value["billing"]
    if billing is not None:
        _exact(billing, {"currency", "input_microunits_per_token_upper", "output_microunits_per_token_upper",
                         "fixed_microunits_per_attempt_upper", "rationale"}, "billing")
        _text(billing["currency"], "billing currency")
        _text(billing["rationale"], "billing rationale")
        for key in ("input_microunits_per_token_upper", "output_microunits_per_token_upper",
                    "fixed_microunits_per_attempt_upper"):
            _integer(billing[key], key)
    return value


def _project(node, request_bytes, unit, policy):
    output = node["execution"]["output_tokens_upper"]
    extra = node["additional_input_tokens_upper"]
    for key, value in (("output_tokens_upper", output), ("additional_input_tokens_upper", extra)):
        if value is not None:
            _integer(value, key)
    if policy["mode"] == "unknown" or output is None or extra is None:
        return None, None
    inputs = _integer(request_bytes * policy["tokens_per_utf8_byte_upper"]
                      + policy["input_overhead_tokens"] + extra, "projected input tokens")
    inputs = max(inputs, unit["estimates"]["context_tokens_p90"])
    tokens = _integer(inputs + output, "projected total tokens")
    billing = policy["billing"]
    if billing is None:
        return tokens, None
    cost = _integer(inputs * billing["input_microunits_per_token_upper"]
                    + output * billing["output_microunits_per_token_upper"]
                    + billing["fixed_microunits_per_attempt_upper"], "projected cost")
    return tokens, cost


def _input_measurements(node):
    _text(node["prompt"], "prompt")
    measurements = {"prompt": _measurement(node["prompt"])}
    for group in ("wrappers", "attachments", "sources"):
        blobs = node[group]
        _require(type(blobs) is list and len(blobs) <= MAX_NODES, f"{group}: bounded list required")
        identities, measured = set(), []
        for blob in blobs:
            _exact(blob, {"id", "text"}, group)
            blob_id = _id(blob["id"], f"{group}.id")
            _require(blob_id not in identities, f"{group}: duplicate identity")
            identities.add(blob_id)
            measured.append({"id": blob_id, **_measurement(blob["text"])})
        measurements[group] = measured
    _require(node["rendered_request"] == render_request(node), "rendered request drift")
    measurements["rendered_request"] = _measurement(node["rendered_request"])
    return measurements


def _check_preparation_estimates(node):
    for field in ("estimate_source", "unit_estimate"):
        value = node[field]
        _require(type(value) is dict, f"{field}: object required")
        _require(not any(key in value for key in work_sizing.REFINEMENT_LINEAGE_FIELDS),
                 "refinement authority is unsupported by preparation")
        profile = value.get("task_profile")
        if type(profile) is dict and type(profile.get("execution_contract")) is dict:
            _require(profile["execution_contract"].get("mode") != "checked-sequence-v1",
                     "checked-sequence normalization is outside offline preparation")


def _exact_context_sources(manifest, sources):
    paths = [entry["path"] for entry in manifest]
    _require(len(paths) == len(set(paths)), "duplicate estimate context manifest path")
    _require(set(paths) == set(sources), "estimate context/source selection mismatch")


def _unit(node, payload, projection, reasons):
    identity = node["id"]
    _text(node["sizing_rationale"], "sizing_rationale")
    uncertainty = _exact(node["uncertainty"], {"status", "detail"}, "unit uncertainty")
    _text(uncertainty["detail"], "unit uncertainty detail")
    _require(uncertainty["status"] in ("bounded", "unresolved"), "unsupported uncertainty status")
    if uncertainty["status"] == "unresolved":
        reasons.append(f"{identity}: unresolved sizing uncertainty")
    execution = _exact(node["execution"], {"executor", "provider", "model", "effort", "options",
                                          "tool_surface", "output_tokens_upper"}, "execution")
    for key in ("executor", "provider", "model", "effort"):
        _text(execution[key], f"execution.{key}")
    _require(type(execution["options"]) is dict, "execution.options must be an object")
    _ids(execution["tool_surface"], "tool_surface")
    measurements = _input_measurements(node)
    _check_preparation_estimates(node)
    source = node["estimate_source"]
    unit = node["unit_estimate"]
    _require(node["source_sha256"] == work_sizing.canonical_work_estimate_sha256(source),
             "stale estimate source digest")
    errors = work_sizing.validate_work_estimate(unit, policy=payload["policy"])
    _require(not errors, "invalid unit estimate: " + "; ".join(errors))
    computed = work_sizing.evaluate_work_estimate(source, policy=payload["policy"])
    digest = work_sizing.canonical_work_estimate_sha256(unit)
    _require(node["unit_sha256"] == digest
             and digest == work_sizing.canonical_work_estimate_sha256(computed), "stale unit digest or source")
    _require(unit["work_unit_id"] == identity and unit["bead_id"] == payload["parent_id"],
             "unit scope identity mismatch")
    _require(unit["requested_model"] == execution["model"], "declared model differs from unit estimate")
    _require(bool(unit["expected_artifacts"]) and bool(unit["acceptance_checks"]), "unit output/acceptance missing")
    manifest = unit["context_manifest"]
    sources = {blob["id"]: _measurement(blob["text"]) for blob in node["sources"]}
    _exact_context_sources(manifest, sources)
    for entry in manifest:
        measured = sources.get(entry["path"])
        _require(measured is not None and entry["bytes"] == measured["bytes"]
                 and entry["sha256"] == measured["sha256"], "estimate context/source bytes drift")
    if unit["hard_gate_reasons"]:
        reasons.append(f"{identity}: existing unit sizing hard gates remain unresolved")
    allowance = unit["aggregate_allowance"]
    amounts = {"tool_calls": _integer(allowance["tool_calls_hard"], "tool_calls_hard"),
               "runtime_seconds": _integer(allowance["runtime_seconds_hard"], "runtime_seconds_hard")}
    amounts["tokens"], amounts["cost_microunits"] = _project(
        node, measurements["rendered_request"]["bytes"], unit, projection)
    return {"id": identity, "role": node["role"], "kind": node["kind"],
            "lineage_parent": node["lineage_parent"], "source_sha256": node["source_sha256"],
            "unit_sha256": digest, "measurements": measurements, "amounts": amounts,
            "execution": execution, "depends_on": list(node["depends_on"]),
            "sizing_rationale": node["sizing_rationale"], "uncertainty": uncertainty}


def _aggregate(nodes, limits):
    totals, checks, reasons = {}, {}, []
    for key in RESOURCES:
        values = [node["amounts"][key] for node in nodes]
        totals[key] = None if any(value is None for value in values) else _integer(sum(values), f"total.{key}")
        if totals[key] is None or limits[key] is None:
            checks[key] = "unknown"
            reasons.append(f"{key}: projection or declared aggregate limit unknown")
        elif totals[key] > limits[key]:
            checks[key] = "exceeded"
            reasons.append(f"{key}: declared aggregate limit exceeded")
        else:
            checks[key] = "within"
    return totals, checks, reasons


def _prepare(payload):
    _tree(payload)
    _exact(payload, {"parent_id", "run_id", "purpose", "output", "acceptance", "aggregate_id",
                     "task_contract", "policy", "policy_sha256", "estimator_version",
                     "projection_policy", "limits", "nodes", "bound_input_sha256"}, "input")
    for key in ("parent_id", "run_id", "aggregate_id"):
        _id(payload[key], key)
    for key in ("purpose", "output"):
        _text(payload[key], key)
    _require(type(payload["acceptance"]) is list and 0 < len(payload["acceptance"]) <= MAX_NODES,
             "acceptance: bounded nonempty list required")
    for criterion in payload["acceptance"]:
        _text(criterion, "acceptance criterion")
    _require(payload["estimator_version"] == ESTIMATOR_VERSION, "estimator version mismatch")
    _require(type(payload["policy"]) is dict, "policy must be an inline object")
    _require(payload["policy_sha256"] == canonical_authority_sha256(payload["policy"]), "policy digest drift")
    digest = input_sha256(payload)
    _require(payload["bound_input_sha256"] == digest, "bound input digest drift")
    limits = _exact(payload["limits"], RESOURCES, "limits")
    for key, value in limits.items():
        if value is not None:
            _integer(value, f"limits.{key}")
    projection = _projection_policy(payload["projection_policy"])
    reasons = []
    nodes = [_unit(node, payload, projection, reasons) for node in _graph(payload)]
    totals, checks, aggregate_reasons = _aggregate(nodes, limits)
    reasons.extend(aggregate_reasons)
    status = ("over-budget" if "exceeded" in checks.values() else
              "unassessable" if reasons else "within-declared-limits")
    return {"status": status, "bound_input_sha256": digest, "aggregate_id": payload["aggregate_id"],
            "parent_id": payload["parent_id"], "run_id": payload["run_id"],
            "purpose": payload["purpose"], "output": payload["output"], "acceptance": payload["acceptance"],
            "task_contract": payload["task_contract"], "projection_policy": projection,
            "policy_sha256": payload["policy_sha256"], "estimator_version": ESTIMATOR_VERSION,
            "totals": totals, "limits": dict(limits), "checks": checks, "nodes": nodes,
            "currency": None if projection["billing"] is None else projection["billing"]["currency"],
            "reasons": reasons}


def prepare(payload):
    """Return a computed diagnostic, including structured failures, without spending."""
    diagnostic = {"operative": False, "qualified": False, "effect_authority": False,
                  "external_completeness_authenticated": False, "actual_quota_known": False,
                  "actual_provider_billing_known": False}
    try:
        diagnostic.update(_prepare(payload))
    except (AuthorityProvenanceError, ValueError, TypeError, KeyError, OverflowError, RecursionError, UnicodeError) as exc:
        diagnostic.update(status="invalid", reasons=[str(exc)])
    return diagnostic


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON object key")
        result[key] = value
    return result


def _constant(value):
    raise ValueError(f"non-finite JSON constant: {value}")


def main(stdin=None, stdout=None):
    """Read one bounded UTF-8 JSON object from stdin; write only a diagnostic."""
    stdin = sys.stdin.buffer if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    try:
        raw = stdin.read(MAX_BYTES + 1)
        _require(type(raw) is bytes and len(raw) <= MAX_BYTES, "UTF-8 byte input exceeds bound or has wrong type")
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
        diagnostic = prepare(payload)
    except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError, OSError) as exc:
        diagnostic = prepare(None)
        diagnostic["reasons"] = [str(exc)]
    stdout.write(json.dumps(diagnostic, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n")
    return 0 if diagnostic["status"] == "within-declared-limits" else 2 if diagnostic["status"] == "invalid" else 1


if __name__ == "__main__":
    raise SystemExit(main())
