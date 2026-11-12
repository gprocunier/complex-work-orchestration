#!/usr/bin/env python3
"""Prepare an inert in-thread proposal from supplied records and real policy."""
from __future__ import annotations

import json
import re
import sys
from typing import Any

from cwo_core import candidate_identity as ci
from cwo_core import requirement_baseline as rb
from cwo_core import routing
from cwo_core.errors import CWOError
from cwo_core.risk_features import assessed_texts, normalized_tokens

MAX_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 32
MAX_NODES = 100_000
MAX_AMENDMENTS = 32
MAX_TEXT = 32_768
MIN_INT, MAX_INT = -(2**63), 2**63 - 1
REQUEST_FIELDS = ("record_type", "version", "baseline", "amendments", "candidate", "task")
TASK_FIELDS = (
    "text", "text_segments", "file_paths", "requested_roles", "data_sensitivity",
    "delegation_requested", "dependencies", "required_reviews", "holds",
)
FALSE_FIELDS = (
    "operative", "qualified", "effect_authority", "production_ready",
    "minimal_tier_available", "successful_closure_available",
    "candidate_current_authenticated", "baseline_custody_authenticated",
)
DELEGATION_WORDS = frozenset({
    "delegate", "delegated", "delegation", "worker", "workers", "workerbee",
    "workerbees", "subagent", "subagents", "contractor", "contractors", "parallel",
})
CONTROL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
CANDIDATE_SCOPE = (
    "The supplied candidate is a structural consistency input, not an observed "
    "current checkout or authenticated custody."
)
INVALIDATION = (
    "Before future acceptance, independently check baseline custody and exact-current "
    "candidate correspondence. Relevant content, baseline, candidate, task or policy "
    "changes require a new proposal and fresh affected observations, reviews and "
    "adjudication. This helper observes no project files or custody."
)


class PreparationError(ValueError):
    """A structured refusal of preparation."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("; ".join(errors))


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise PreparationError([message])


def _response() -> dict[str, Any]:
    return {
        **dict.fromkeys(FALSE_FIELDS, False),
        "record_type": "cwo-in-thread-plan-preparation",
        "version": 1,
        "status": "refused",
        "shape": None,
        "errors": [],
        "nodes": [],
        "candidate_scope": CANDIDATE_SCOPE,
        "future_invalidation_requirement": INVALIDATION,
        "open_requirements": ["Full production closure qualification remains open.", "In-thread plan activation remains open."],
    }


def _closed(value: Any, fields: tuple[str, ...], where: str) -> None:
    _need(type(value) is dict, f"{where} must be an object.")
    _need(set(value) == set(fields), f"{where} has missing or unsupported fields.")


def _children(value: Any) -> list[Any]:
    if type(value) is dict:
        _need(all(type(key) is str for key in value), "Object keys must be text.")
        _need(len(value) <= MAX_NODES, "Input exceeds the node limit.")
        return [child for pair in value.items() for child in pair]
    if type(value) is list:
        _need(len(value) <= MAX_NODES, "Input exceeds the node limit.")
        return value
    if type(value) is str:
        _need(len(value) <= MAX_BYTES, "Input text exceeds the byte limit.")
        value.encode("utf-8")
    elif type(value) is int:
        _need(MIN_INT <= value <= MAX_INT, "Input integers must be signed 64-bit values.")
    else:
        _need(value is None or type(value) is bool, "Input contains an unsupported JSON type.")
    return []


def _bounded_tree(value: Any) -> None:
    pending = [(value, 1)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        _need(count <= MAX_NODES and depth <= MAX_DEPTH, "Input exceeds the node or depth limit.")
        pending.extend((child, depth + 1) for child in _children(item))


def _text(value: Any, where: str) -> None:
    _need(type(value) is str and bool(value.strip()), f"{where} must be non-empty text.")
    _need(len(value) <= MAX_TEXT and not CONTROL.search(value), f"{where} contains unsupported text.")


def _texts(value: Any, where: str, limit: int) -> None:
    _need(type(value) is list and len(value) <= limit, f"{where} must be a bounded list.")
    for item in value:
        _text(item, where)


def _named_obligations(value: Any, where: str, *, dependencies: bool = False) -> None:
    _need(type(value) is list and len(value) <= 64, f"{where} must be a bounded list.")
    seen = set()
    fields = ("id", "reason", "kind") if dependencies else ("id", "reason")
    for item in value:
        _closed(item, fields, where)
        _text(item["id"], where)
        _text(item["reason"], where)
        _need(
            re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]{0,63}", item["id"]) is not None,
            f"{where} needs stable IDs.",
        )
        _need(item["id"].casefold() not in seen, f"{where} repeats an ID.")
        seen.add(item["id"].casefold())
        if dependencies:
            _need(item["kind"] in ("internal", "external"), "Dependency kind is unsupported.")


def _validate_task(task: Any) -> None:
    _closed(task, TASK_FIELDS, "Task context")
    _text(task["text"], "Original text")
    _texts(task["text_segments"], "Original text segments", 32)
    _need(bool(task["text_segments"]), "Original ordered text segments are required.")
    _need(
        task["text"] == "\n".join(task["text_segments"]),
        "Original text must retain the ordered segments joined by newlines.",
    )
    _texts(task["file_paths"], "File paths", 64)
    _need(bool(task["file_paths"]), "Original file paths are required.")
    _need(len(set(task["file_paths"])) == len(task["file_paths"]), "File paths repeat.")
    for path in task["file_paths"]:
        _need(not path.startswith("/") and "\\" not in path, "File paths must be relative.")
        _need(
            all(part not in ("", ".", "..") for part in path.split("/")),
            "File path components are unsupported.",
        )
    _texts(task["requested_roles"], "Requested roles", 32)
    _need(
        task["data_sensitivity"] in (None, "public", "redacted", "internal", "restricted"),
        "Data sensitivity is unsupported.",
    )
    _need(type(task["delegation_requested"]) is bool, "Delegation context must be boolean.")
    _named_obligations(task["dependencies"], "Named dependencies", dependencies=True)
    _named_obligations(task["required_reviews"], "Required review obligations")
    _named_obligations(task["holds"], "Applicable holds")


def _request(value: Any) -> dict[str, Any]:
    _bounded_tree(value)
    _need(
        len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")) <= MAX_BYTES,
        "Input exceeds the serialized byte limit.",
    )
    _closed(value, REQUEST_FIELDS, "Request")
    _need(
        value["record_type"] == "cwo-in-thread-plan-request" and type(value["version"]) is int and value["version"] == 1,
        "Only version 1 in-thread plan requests are supported.",
    )
    _need(
        type(value["amendments"]) is list and len(value["amendments"]) <= MAX_AMENDMENTS,
        "Amendments must be an ordered list of at most 32 records.",
    )
    _validate_task(value["task"])
    return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))


def _chain_and_candidate(request: dict[str, Any]) -> dict[str, Any]:
    errors = rb.baseline_errors(request["baseline"])
    if errors:
        raise PreparationError(errors)
    chain = rb.resolve_chain(request["baseline"], request["amendments"])
    errors = ci.candidate_errors(request["candidate"])
    if not errors:
        errors = ci.baseline_binding_errors(request["candidate"], chain)
    if errors:
        raise PreparationError(errors)
    return chain


def _classify(task: dict[str, Any]) -> dict[str, Any]:
    return routing.classify_work(
        task["text"],
        text_segments=task["text_segments"],
        file_paths=task["file_paths"],
        requested_roles=task["requested_roles"],
        data_sensitivity=task["data_sensitivity"],
        share_boundary="no-outside-sharing",
        external_ok=False, local_ok=False, prefer_local=False,
        allow_disclosure_escalation=False, current_authority=None,
        operative_evaluated_at="2000-01-01T00:00:00Z",
    )


def _registered_role_experts() -> dict[str, set[str]]:
    aliases: dict[str, set[str]] = {}
    for name, profile in routing.load_policy("expert-registry")["experts"].items():
        values = [name, profile.get("discipline", ""), profile.get("job_description_label", "")]
        values.extend(profile.get("aliases", []))
        for value in values:
            if value:
                aliases.setdefault(value.lower(), set()).add(name)
    return aliases


def _requested_role_reasons(task: dict[str, Any], route: dict[str, Any]) -> list[str]:
    if not task["requested_roles"]:
        return []
    registered = _registered_role_experts()
    routed = {expert["name"] for expert in route["ranked_experts"]}
    reasons = []
    for index, role in enumerate(task["requested_roles"]):
        matches = registered.get(role.lower(), set())
        if not matches:
            reasons.append(f"Requested role at index {index} is not registered in the real expert registry.")
        else:
            missing = sorted(matches - routed)
            if missing:
                reasons.append(f"Requested role at index {index} has unaccounted experts: {', '.join(missing)}.")
    return reasons


def _expert_reasons(route: dict[str, Any]) -> list[str]:
    reasons = []
    for expert in route["ranked_experts"]:
        selected = expert["selected_executor"]
        mandatory = bool(
            expert.get("validation_gate_required")
            or expert.get("executor_policy_violations")
        )
        delegated = bool(
            selected.get("external")
            or selected.get("dispatch_mode") in routing.LOCAL_DISPATCH_MODES
        )
        # Worker acceptance applies when a worker result is used.
        # This manual proposal selects, launches and accepts no worker.
        restricted = selected.get("codex_pickup") == "forbidden"
        if mandatory or delegated or restricted:
            reasons.append(f"Expert {expert['name']} retains a required review or restricted executor.")
        if expert["name"] not in routing.DOC_SAFE_EXPERTS_FOR_TRIVIAL_CHANGE:
            reasons.append(f"Expert {expert['name']} needs a consequential plan.")
    return reasons


def _routing_reasons(route: dict[str, Any]) -> list[str]:
    assessment = route["risk_assessment"]
    checks = [
        (route["risk_level"] != "low", "Actual policy risk is not low."),
        (route["route"] != "internal-worker", "Actual policy route is not in-thread work."),
        (
            bool(assessment["features"] or assessment["required_experts"] or assessment["unmet_required_experts"]),
            "Actual risk features and expert obligations need a consequential plan.",
        ),
        (bool(route["hard_stops"]), "Actual policy hard stops remain."),
        (
            bool(route["external_experts"] or route["local_worker_experts"] or route["acceptance_required_experts"]),
            "Actual contracted review dependencies remain.",
        ),
        (
            bool(route["requested_architecture_critic_executors"] or route["architecture_critic_contracts"]),
            "Named critic dependencies remain.",
        ),
        (route["model_synthesis"].get("active") is True or route["model_synthesis"].get("recommended_mode") not in (None, "none"),
         "Model synthesis needs a consequential plan."),
    ]
    reasons = [message for blocked, message in checks if blocked]
    reasons.extend(
        f"Policy obligation {key} remains required or unresolved."
        for key, value in sorted(route.items())
        if key.endswith("_required") and key != "beads_required_for_full_handoff" and value is not False
    )
    return reasons + _expert_reasons(route)


def _context_reasons(request: dict[str, Any]) -> list[str]:
    task, candidate = request["task"], request["candidate"]
    tokens = {
        token
        for text in assessed_texts(task["text"], task["text_segments"])
        for token in normalized_tokens(text)
    }
    checks = [
        (task["delegation_requested"] or bool(tokens & DELEGATION_WORDS),
         "Delegation context needs a consequential plan."),
        (bool(task["dependencies"]), "Every declared dependency remains open in a consequential plan."),
        (bool(task["required_reviews"]), "Every declared required review remains open."),
        (bool(task["holds"]), "Every declared hold remains in effect."),
        (not routing.trivial_single_file_docs_change(task["text"], task["file_paths"]),
         "The original scope is outside the bounded trivial documentation case."),
        (candidate["delivery_scope"]["paths"] != sorted(task["file_paths"]),
         "Candidate scope and original file paths need reconciliation."),
        (any(entry["path"] not in task["file_paths"] for entry in candidate["worktree_manifest"]),
         "Candidate changes include paths outside the original routing context."),
    ]
    return [message for blocked, message in checks if blocked]


def _node(node_id, kind, deps, text, criteria=()):
    return {
        "id": node_id,
        "kind": kind,
        "depends_on": deps,
        "criterion_ids": list(criteria),
        "obligation": text,
    }


def _nodes(chain: dict[str, Any], route: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = [
        _node(
            "binding", "binding", [],
            "Require independent baseline custody and exact-current candidate checks before future acceptance.",
        ),
        _node(
            "content", "content", ["binding"],
            "Produce all scoped code, documentation and examples before final observations and reviews.",
        ),
    ]
    finals = ["content"]
    for criterion in chain["baseline"]["criteria"]:
        if criterion["applicability"] == "required":
            node_id = "criterion:" + criterion["id"]
            nodes.append(_node(
                node_id, "obligation", ["content"],
                f"Require independent {criterion['evidence_kind']} evidence on the finished candidate for this criterion.",
                (criterion["id"],),
            ))
            finals.append(node_id)
    for expert in route["ranked_experts"]:
        node_id = "review:" + expert["name"]
        nodes.append(_node(
            node_id, "review", finals.copy(),
            f"Retain the {expert['name']} review recommendation for future independent disposition. "
            "No review is accepted.",
        ))
    review_ids = [node["id"] for node in nodes if node["kind"] == "review"]
    nodes.append(_node(
        "adjudication", "review", [*finals, *review_ids],
        "Require future candidate-bound adjudication of all applicable acceptance obligations and findings.",
    ))
    nodes.append(_node(
        "disclosure", "disclosure", ["adjudication"],
        "Disclose limitations, unobserved evidence, remaining holds and the absence of acceptance authority.",
    ))
    nodes.append(_node(
        "report", "report", ["disclosure"],
        "Report the proposal and remaining work without modifying files, Beads or acceptance state.",
    ))
    return nodes


def prepare_proposal(value: Any) -> dict[str, Any]:
    """Prepare obligations only; supplied identity records do not establish custody."""
    result = _response()
    try:
        request = _request(value)
        chain = _chain_and_candidate(request)
        result.update(
            baseline_chain=chain, candidate=request["candidate"], task_context=request["task"],
            candidate_digest=ci.candidate_digest(request["candidate"]),
            applicability=[
                {
                    "criterion_id": item["id"],
                    "applicability": item["applicability"],
                    "reason": item.get("not_applicable_reason",
                                       "The independent baseline marks this criterion as required."),
                }
                for item in chain["baseline"]["criteria"]
            ],
        )
        route = _classify(request["task"])
        result["routing_recommendation"] = route
        result["routing_scope"] = "Real policy recommendation only; no dispatch, operative authority or admission."
        reasons = _requested_role_reasons(request["task"], route)
        reasons += _routing_reasons(route) + _context_reasons(request)
        result["status"] = "consequential-plan-needed" if reasons else "proposed-in-thread"
        result["errors"] = reasons
        if not reasons:
            result["shape"] = "proposed-in-thread"
            result["nodes"] = _nodes(chain, route)
        result["proposal_binding"] = rb.record_digest({
            "request": request, "routing": route, "nodes": result["nodes"], "version": 1,
        })
    except (PreparationError, rb.RequirementBaselineError) as error:
        result.update(status="refused", shape=None, nodes=[], errors=error.errors)
    except (CWOError, OSError, ValueError, TypeError, KeyError, RecursionError, SystemExit):
        result["status"] = "refused"
        result["shape"] = None
        result["nodes"] = []
        result["errors"] = ["Record validation or the real policy classifier could not prepare a proposal."]
    return result


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        _need(key not in result, "JSON contains duplicate object keys.")
        result[key] = value
    return result


def _json_int(text: str) -> int:
    _need(len(text.lstrip("-")) <= 19, "JSON integer exceeds the signed 64-bit limit.")
    value = int(text)
    _need(MIN_INT <= value <= MAX_INT, "JSON integer exceeds the signed 64-bit limit.")
    return value


def _no_number(text: str) -> None:
    raise PreparationError(["JSON floats and nonfinite numbers are unsupported."])


def _scan_json(text: str) -> None:
    depth, tokens = 0, 0
    quoted, escaped = False, False
    for char in text:
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif not quoted:
            depth += (char in "[{") - (char in "]}")
            tokens += char in "[{,:"
            _need(depth <= MAX_DEPTH, "JSON exceeds the depth limit.")
            _need(tokens <= MAX_NODES, "JSON exceeds the structural node limit.")


def prepare_json(raw: bytes) -> dict[str, Any]:
    """Decode bounded stdin bytes without changing parser settings."""
    try:
        _need(
            type(raw) is bytes and len(raw) <= MAX_BYTES,
            "Input must be at most 4 MiB of UTF-8 JSON bytes.",
        )
        text = raw.decode("utf-8")
        _scan_json(text)
        value = json.loads(
            text, object_pairs_hook=_unique, parse_int=_json_int, parse_float=_no_number, parse_constant=_no_number,
        )
    except PreparationError as error:
        return {**_response(), "errors": error.errors}
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return {**_response(), "errors": ["Input cannot be decoded as bounded UTF-8 JSON."]}
    return prepare_proposal(value)


def main(argv: list[str] | None = None, *, stdin=None, stdout=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    destination = sys.stdout if stdout is None else stdout
    if args:
        result = {**_response(), "errors": ["This CLI accepts bounded JSON on stdin and no arguments."]}
    else:
        source = sys.stdin.buffer if stdin is None else stdin
        try:
            result = prepare_json(source.read(MAX_BYTES + 1))
        except (OSError, ValueError, TypeError, UnicodeError):
            result = {**_response(), "errors": ["Standard input could not be read as bounded JSON bytes."]}
    rendered = json.dumps(
        result, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    ) + "\n"
    if len(rendered.encode("ascii")) > MAX_OUTPUT_BYTES:
        rendered = json.dumps(
            {**_response(), "errors": ["The proposal exceeds the bounded stdout size."]},
            sort_keys=True,
        ) + "\n"
        result = _response()
    destination.write(rendered)
    return 0 if result["status"] == "proposed-in-thread" else 1


if __name__ == "__main__":
    raise SystemExit(main())
