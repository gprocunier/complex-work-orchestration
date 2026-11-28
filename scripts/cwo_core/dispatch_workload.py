"""Check whole-route sizing at a managed text dispatch boundary."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat

from . import route_feasibility
from .paths import POLICY_DIR
from .policy_schema import strict_json_loads

WORKLOAD_FIELDS = {"route_input", "node_id"}
POLICY_FILE = POLICY_DIR / "native-worker-execution.yaml"


class WorkloadRefused(ValueError):
    """Dispatch has no current, matching workload sizing."""


def _require(condition, reason):
    if not condition:
        raise WorkloadRefused(f"workload sizing refused: {reason}")


def _read_document(path, captures=None):
    try:
        source = Path(path).absolute()
        descriptor = os.open(source, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as stream:
            _require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "input must be a regular file")
            raw = stream.read(route_feasibility.MAX_BYTES + 1)
        _require(len(raw) <= route_feasibility.MAX_BYTES, "input file exceeds the byte limit")
        value = strict_json_loads(raw.decode("utf-8"))
    except (OSError, ValueError, RecursionError):
        raise WorkloadRefused("workload sizing refused: invalid workload or policy file") from None
    if captures is not None:
        captures.append((str(source), raw))
    return value


def read_export_workload(path, captures=None):
    """Read the original workload without printing its contents."""
    if path is None:
        raise WorkloadRefused("workload sizing required: supply --workload")
    return _read_document(path, captures)


def _check_request(node, route, request_text, wire_text):
    _require(node["prompt"] == request_text and request_text in wire_text, "selected prompt differs from the request")
    for group in ("wrappers", "attachments", "sources"):
        _require(all(entry["text"] in wire_text for entry in node[group]), "declared request components are absent")
    wire = wire_text.encode("utf-8")
    extra = len(wire) - len(request_text.encode("utf-8"))
    rate = route["projection_policy"]["tokens_per_utf8_byte_upper"]
    _require(node["additional_input_tokens_upper"] >= extra * rate, "request overhead exceeds the input allowance")
    return hashlib.sha256(wire).hexdigest()


def validate_export_workload(workload, *, request_text, executor, provider, model=None, effort=None,
                             bead_id=None, wire_text=None, captures=None):
    """Recompute current sizing for the actual request with declared runtime and cost bounds."""
    _require(type(workload) is dict and set(workload) == WORKLOAD_FIELDS, "expected original route and selected node")
    route = workload["route_input"]
    policy = _read_document(POLICY_FILE, captures)
    _require(type(route) is dict and route.get("policy_sha256") == route_feasibility.canonical_authority_sha256(policy),
             "original route does not match current planning policy")
    plan = route_feasibility.prepare(route)
    _require(plan["status"] == "within-declared-limits", "original route failed complete feasibility checks")
    selected = next((node for node in plan["nodes"] if node["id"] == workload["node_id"]), None)
    _require(selected is not None and selected["kind"] == "primary", "dispatch requires a ready primary node")
    _require(bead_id is None or bead_id == route["parent_id"], "original route belongs to a different Bead")
    execution = selected["execution"]
    expected = {"executor": executor, "provider": provider, "model": model, "effort": effort}
    _require(all(value is None or execution[key] == value for key, value in expected.items()),
             "selected executor, provider, model or effort differs from dispatch")
    amounts = selected["amounts"]
    _require(min(amounts["runtime_seconds"], amounts["tokens"], execution["output_tokens_upper"]) > 0,
             "dispatch requires positive runtime, token and output allowances")
    node = next(node for node in route["nodes"] if node["id"] == selected["id"])
    digest = _check_request(node, route, request_text, request_text if wire_text is None else wire_text)
    return {"route_sha256": plan["bound_input_sha256"], "policy_sha256": plan["policy_sha256"],
            "unit_sha256": selected["unit_sha256"], "request_sha256": digest, "node_id": node["id"],
            "amounts": amounts, "execution": execution}
