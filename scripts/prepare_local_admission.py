"""Offline workload admission with caller-supplied fake effects and conservative accounting."""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field, fields
from pathlib import Path

import prepare_route_feasibility as planner
import prepare_route_ledger_reconciliation as reconciliation
from cwo_core.invocation_ledger import InvocationLedger, request_sha256

ledger_api = reconciliation.ledger
POLICY_PATH = Path(__file__).resolve().parents[1] / "policy" / "native-worker-execution.yaml"
MAX_LIFETIME_SECONDS = 3600
FALSE_FIELDS = ("production_ready", "effect_authority", "operative", "qualified")


class AdmissionError(ValueError):
    """An offline admission failed a required consistency check."""


@dataclass(frozen=True, slots=True)
class PreparedAdmission:
    """Immutable offline bindings; construction alone does not authenticate custody."""

    route_input_bytes: bytes
    node_id: str
    selected_node_bytes: bytes
    request_bytes: bytes
    policy_bytes: bytes
    plan_bytes: bytes
    aggregate_context_bytes: bytes
    scope_sha256: str
    budget_id: str
    amounts_bytes: bytes
    limits_bytes: bytes
    planned_totals_bytes: bytes
    execution_bytes: bytes
    issued_at: int | float
    expires_at: int | float
    production_ready: bool = field(default=False, init=False)
    effect_authority: bool = field(default=False, init=False)
    operative: bool = field(default=False, init=False)
    qualified: bool = field(default=False, init=False)


def _require(condition, reason):
    if not condition:
        raise AdmissionError(reason)


def _time(value):
    _require(type(value) in (int, float), "Offline admission time must be a finite number.")
    if type(value) is float:
        _require(math.isfinite(value), "Offline admission time must be finite.")
    _require(0 <= value <= ledger_api.MAX_TIME, "Offline admission time exceeds the ledger bound.")


def _times(now, expires_at):
    _time(now)
    _time(expires_at)
    _require(0 < expires_at - now <= MAX_LIFETIME_SECONDS,
             "Offline admission expiry must follow issue time by at most one hour.")


def _read_policy_bytes():
    with POLICY_PATH.open("rb") as handle:
        raw = handle.read(reconciliation.MAX_BYTES + 1)
    _require(type(raw) is bytes and len(raw) <= reconciliation.MAX_BYTES,
             "Current planning policy exceeds the offline byte bound.")
    return raw


def _plan(route_input):
    route, original = reconciliation._snapshot(route_input)
    _require(type(route) is dict, "Offline admission requires the original route object.")
    policy_bytes = _read_policy_bytes()
    policy = reconciliation._decode(policy_bytes)
    _require(type(policy) is dict, "Current planning policy must be an object.")
    _require(reconciliation._same(route.get("policy"), policy),
             "Inline planning policy differs from the actual current policy file.")
    diagnostic, plan_bytes = reconciliation._snapshot(
        planner.prepare(reconciliation._decode(original)))
    _require(diagnostic["status"] == "within-declared-limits",
             "Original whole-route input failed the real planner's complete feasibility check.")
    return route, original, policy_bytes, diagnostic, plan_bytes


def _resource_bytes(value, label):
    _require(type(value) is dict and set(value) == set(planner.RESOURCES),
             label + " must contain exactly the four offline resource dimensions.")
    for amount in value.values():
        _require(type(amount) is int and 0 < amount <= ledger_api.MAX_UNITS,
                 label + " requires known, strictly positive integer resource amounts.")
    return reconciliation._encode(value)


def prepare(route_input, node_id, *, now, expires_at):
    """Prepare immutable offline node admission from actual whole-route planning."""
    _times(now, expires_at)
    _require(type(node_id) is str, "Offline admission requires an exact string node identity.")
    route, original, policy_bytes, plan, plan_bytes = _plan(route_input)
    limits_bytes = _resource_bytes(plan["limits"], "Declared aggregate limits")
    totals_bytes = _resource_bytes(plan["totals"], "Computed whole-route totals")
    for node in plan["nodes"]:
        _resource_bytes(node["amounts"], "Computed node allowance")
    nodes = {node["id"]: node for node in plan["nodes"]}
    _require(node_id in nodes, "Selected offline node is missing from the original route.")
    selected = nodes[node_id]
    original_node = next(node for node in route["nodes"] if node["id"] == node_id)
    context = reconciliation.scope_context(route)
    return PreparedAdmission(
        route_input_bytes=original, node_id=node_id,
        selected_node_bytes=reconciliation._encode(original_node),
        request_bytes=original_node["rendered_request"].encode("utf-8"),
        policy_bytes=policy_bytes, plan_bytes=plan_bytes,
        aggregate_context_bytes=reconciliation._encode(context),
        scope_sha256=reconciliation.scope_sha256(context), budget_id=route["aggregate_id"],
        amounts_bytes=_resource_bytes(selected["amounts"], "Selected node allowance"),
        limits_bytes=limits_bytes, planned_totals_bytes=totals_bytes,
        execution_bytes=reconciliation._encode(selected["execution"]),
        issued_at=now, expires_at=expires_at,
    )


def _same_admission(received, expected):
    return all(
        type(getattr(received, item.name)) is type(getattr(expected, item.name))
        and getattr(received, item.name) == getattr(expected, item.name)
        for item in fields(PreparedAdmission)
    )


def _receipt_sha256(admission):
    values = {}
    for item in fields(PreparedAdmission):
        value = getattr(admission, item.name)
        values[item.name] = value.decode("utf-8") if type(value) is bytes else value
    return request_sha256(reconciliation._encode(values))


def _callbacks(effect, observer):
    _require(callable(effect), "Offline invocation requires a caller-supplied fake effect.")
    if observer is not None:
        _require(callable(observer), "Offline observer must be callable.")
        name = getattr(observer, "__qualname__", type(observer).__name__)
        _require(type(name) is str and bool(name.strip()), "Offline observer requires a nonempty name.")


def _live(admission, ledger):
    _require(_read_policy_bytes() == admission.policy_bytes,
             "Current planning policy bytes changed after offline admission.")
    now = ledger.current_time()
    _require(admission.issued_at <= now < admission.expires_at,
             "Offline admission is expired or its issue time is in the future.")


def _validated(admission, expected_route_input, node_id, ledger, effect, observer):
    _require(type(admission) is PreparedAdmission, "A complete immutable offline admission is required.")
    _require(all(hasattr(admission, item.name) for item in fields(PreparedAdmission)),
             "Offline admission record is incomplete.")
    _require(type(ledger) is InvocationLedger, "Offline invocation requires the actual InvocationLedger.")
    _callbacks(effect, observer)
    fresh = prepare(expected_route_input, node_id,
                    now=admission.issued_at, expires_at=admission.expires_at)
    _require(_same_admission(admission, fresh), "Offline admission bindings differ from independent input.")
    _live(fresh, ledger)
    return fresh


def _ledger_require(condition, reason):
    if not condition:
        raise ledger_api.InvocationLedgerError(reason)


def _prior_attempts(fresh, supplied):
    nodes = {node["id"] for node in json.loads(fresh.plan_bytes)["nodes"]}
    if supplied is None:
        return {}
    _require(type(supplied) is dict and len(supplied) <= planner.MAX_NODES,
             "Prior offline attempts require a bounded node mapping.")
    result = {}
    for name, attempt_id in supplied.items():
        _require(type(name) is str and name in nodes and name != fresh.node_id,
                 "Prior offline mapping must name another exact declared node.")
        _require(type(attempt_id) is str and ledger_api._is_id(attempt_id),
                 "Prior offline mapping requires an exact ledger attempt identity.")
        result[name] = attempt_id
    _require(len(set(result.values())) == len(result),
             "Prior offline mapping must use distinct actual attempts.")
    return result


def _graph_lineage(node, mapping):
    parent = node["lineage_parent"]
    _require(parent is None or parent in mapping,
             "Declared offline lineage requires its actual mapped parent.")
    return {"kind": {"primary": "initial", "dependent": "successor"}.get(node["kind"], node["kind"]),
            "parent_attempt_id": None if parent is None else mapping[parent]}


def _one_request(document, node_id, attempt_id):
    recorded = [item["attempt_id"] for item in document["attempts"].values()
                if item["request_id"] == node_id]
    _ledger_require(recorded == [] if attempt_id is None else recorded == [attempt_id],
                    "Offline node request already has an attempt or its mapping differs.")


def _fixed_budget(fresh, document, mapping):
    budget = document["budgets"].get(fresh.budget_id)
    if budget is None:
        _ledger_require(not mapping, "Mapped offline attempts require the original aggregate budget.")
        return
    _ledger_require(budget["scope_sha256"] == fresh.scope_sha256
                    and reconciliation._same(budget["limits"], json.loads(fresh.limits_bytes)),
                    "Offline aggregate scope and limits must retain their original binding.")


def _known_budget(ledger, document, budget_id):
    for attempt in document["attempts"].values():
        if attempt["budget_id"] != budget_id:
            continue
        _ledger_require(ledger._unresolved_problem(attempt) is None,
                        "Offline aggregate has unresolved intent or requires reconciliation.")
        _ledger_require(attempt["state"] != "terminal"
                        or attempt["outcome"] not in ("unknown", "timeout", "cancelled", "reconciled"),
                        "Offline aggregate retains an unsupported or unknown effect outcome.")


def _ready_dependency(node, dependency, attempt, ledger, now):
    parent = dependency == node["lineage_parent"]
    if parent and node["kind"] == "sibling" and attempt["state"] in ("reserved", "invocation-intent"):
        _ledger_require(ledger.owner_probe.status(attempt["owner"]) == "alive",
                        "A pending offline sibling parent requires a known live owner.")
        _ledger_require(attempt["state"] != "reserved" or now < attempt["expires_at"],
                        "A pending offline sibling parent reservation has expired.")
        return
    outcomes = ("failed",) if parent and node["kind"] in ("retry", "fallback") else ("completed",)
    _ledger_require(attempt["state"] == "terminal" and attempt["outcome"] in outcomes,
                    "Offline dependency lacks the supported terminal outcome for its declared kind.")


def _dependencies(node, mapping, attempts, child=None):
    result = []
    for dependency in node["depends_on"]:
        _require(dependency in mapping, "Every direct offline dependency requires an actual mapped attempt.")
        attempt = attempts.get(mapping[dependency])
        _ledger_require(attempt is not None, "Mapped offline dependency is missing from the actual ledger.")
        if child is not None:
            _ledger_require(attempt["sequence"] < child["sequence"]
                            and attempt["created_at"] <= child["created_at"],
                            "Offline dependency reservation must precede its child in the actual ledger.")
        result.append((dependency, attempt))
    return result


def _reserved_deadlines(dependencies):
    return [attempt["expires_at"] for _dependency, attempt in dependencies
            if attempt["state"] == "reserved"]


def _ready_dependencies(node, mapping, attempts, ledger, now):
    dependencies = _dependencies(node, mapping, attempts)
    for dependency, attempt in dependencies:
        _ready_dependency(node, dependency, attempt, ledger, now)
    return _reserved_deadlines(dependencies)


def _matched_attempt(fresh, node, original, mapping, document, now):
    attempt_id = mapping[node["id"]]
    attempt = document["attempts"].get(attempt_id)
    _ledger_require(attempt is not None, "Mapped offline attempt is missing from the actual ledger.")
    _one_request(document, node["id"], attempt_id)
    _ledger_require(attempt["budget_id"] == fresh.budget_id and attempt["request_id"] == node["id"],
                    "Mapped offline attempt must retain its original aggregate and node request identity.")
    _ledger_require(attempt["request_sha256"] == request_sha256(original["rendered_request"].encode("utf-8")),
                    "Mapped offline rendered request digest differs from the original node.")
    _ledger_require(reconciliation._same(attempt["amount"], node["amounts"]),
                    "Mapped offline allowance differs from the real planner's four-resource amount.")
    _ledger_require(reconciliation._same(attempt["lineage"], _graph_lineage(node, mapping)),
                    "Mapped offline lineage differs from the declared graph.")
    _ledger_require(attempt["created_at"] <= now and attempt["history"][-1]["at"] <= now,
                    "Mapped offline attempt has a future ledger transition.")
    return attempt


def _final_deadlines(fresh, ledger, deadlines):
    _require(_read_policy_bytes() == fresh.policy_bytes,
             "Current planning policy bytes changed after offline admission.")
    now = ledger.current_time()
    _require(fresh.issued_at <= now < fresh.expires_at,
             "Offline admission is expired or its issue time is in the future.")
    _ledger_require(all(now < deadline for deadline in deadlines),
                    "A pending offline dependency reservation has expired.")


def _graph_state(fresh, prior, ledger, current_attempt_id=None):
    nodes = {node["id"]: node for node in json.loads(fresh.plan_bytes)["nodes"]}
    originals = {node["id"]: node for node in json.loads(fresh.route_input_bytes)["nodes"]}
    mapping = dict(prior)
    if current_attempt_id is not None:
        mapping[fresh.node_id] = current_attempt_id
    with ledger._locked() as (_root, document):
        now = ledger.current_time()
        _fixed_budget(fresh, document, mapping)
        _known_budget(ledger, document, fresh.budget_id)
        for name in mapping:
            attempt = _matched_attempt(fresh, nodes[name], originals[name], mapping, document, now)
            _dependencies(nodes[name], mapping, document["attempts"], attempt)
        deadlines = _ready_dependencies(nodes[fresh.node_id], mapping, document["attempts"], ledger, now)
        if current_attempt_id is None:
            _one_request(document, fresh.node_id, None)
        else:
            current = document["attempts"][current_attempt_id]
            _ledger_require(current["state"] == "invocation-intent",
                            "Offline fake effect requires its persisted invocation intent.")
            ledger._require_owner(current)
            charged = ledger._charged(document, fresh.budget_id)
            _require(all(charged[name] <= limit for name, limit in json.loads(fresh.limits_bytes).items()),
                     "Offline aggregate allowance was exhausted during observation.")
            _final_deadlines(fresh, ledger, deadlines)
    return _graph_lineage(nodes[fresh.node_id], prior)


def invoke_offline(admission, expected_route_input, node_id, *,
                   ledger, effect, observer=None, node_attempts=None):
    """Consume declared offline graph admission through the real ledger and supplied fake effect."""
    fresh = _validated(admission, expected_route_input, node_id, ledger, effect, observer)
    prior = _prior_attempts(fresh, node_attempts)
    lineage = _graph_state(fresh, prior, ledger)
    limits = json.loads(fresh.limits_bytes)
    amounts = json.loads(fresh.amounts_bytes)
    ledger.open_budget(fresh.budget_id, limits, scope_sha256=fresh.scope_sha256)
    reservation = ledger.reserve(
        budget_id=fresh.budget_id, request_id=fresh.node_id,
        request_sha256=request_sha256(fresh.request_bytes),
        admission_sha256=_receipt_sha256(fresh),
        amount=amounts, expires_at=fresh.expires_at,
        lineage=lineage,
        refuse_while_unresolved=True,
    )

    def fake_effect(frozen, report):
        execution = json.loads(fresh.execution_bytes)
        allowances = json.loads(fresh.amounts_bytes)
        _live(fresh, ledger)
        _graph_state(fresh, prior, ledger, reservation["attempt_id"])
        return effect(frozen, execution, allowances, report)

    final = ledger.invoke(
        reservation["reservation_id"], fresh.request_bytes, fake_effect,
        observers=() if observer is None else (observer,),
    )
    return {"api": "offline-only-local-admission-v1", "status": "offline-effect-finished",
            "attempt": final, **dict.fromkeys(FALSE_FIELDS, False)}
