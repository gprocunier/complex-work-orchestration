"""Redact owned Codex rollout observations and render the contained-pool record."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date as Date
import re
from typing import Any, Literal, Mapping, Sequence

from .native_pool_deferred_context import QUALIFICATION_EFFORT, QUALIFICATION_MODEL, QUALIFICATION_TIER, QUALIFICATION_TOOL
from .native_pool_qualification_budget import CAMPAIGN_MAX_START_CAP
from .native_session_boundary import (
    NativeSessionBoundaryError,
    record_indices,
    trusted_terminal_event,
)


REQUIRED_BEHAVIORS = (
    "n2_concurrency",
    "n3_concurrency",
    "readonly_workspace",
    "registered_writer",
    "cross_worker_isolation",
    "named_profile",
    "login_path_denied",
    "profile_cannot_widen",
    "provider_only_egress",
    "dedicated_logins",
    "cleanup",
    "failure_isolation",
    "shared_budget",
)
_EXPECTED_TOOLS = (QUALIFICATION_TOOL,)
_TOOL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*")
_CREDENTIAL_PREFIX = re.compile(r"(?:^|\.)(?:sk[-_]|gh[pousr]_|github_pat_|xox[baprs]-|eyJ|AKIA)")
_DIGEST = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_CODE_MODE_HEADING = re.compile(r"^### `([^`\r\n]+)`[ \t]*$", re.MULTILINE)
_VERSION = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:alpha|beta|rc)\.[0-9]+)?", re.ASCII)
_MAX_NAMES = 256
_TOOL_LIMITATIONS = {
    "registration-unavailable": "The rollout has no singular readable dynamic registration list.",
    "turn-unbound": "The rollout has no unambiguous boundary for this turn's catalog declarations.",
    "terminal-unavailable": "The observed turn has no durable terminal marker in this capture.",
    "declarations-unavailable": "No catalog declarations were readable in the selected turn.",
    "declarations-incomplete": "Some declaration entries could not be read safely.",
}
CatalogMode = Literal["trimmed", "stock-fallback"]


@dataclass(frozen=True)
class WorkerToolObservation:
    """Names from an observed rollout, grouped by their original source."""

    world_state_tools: tuple[str, ...] = ()
    additional_tools: tuple[str, ...] = ()
    code_mode_tools: tuple[str, ...] = ()
    registered_tools: tuple[str, ...] = ()
    unexpected: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ("turn-unbound", "declarations-unavailable", "registration-unavailable")


@dataclass(frozen=True)
class OutcomeObservation:
    """Original trusted check outcome and the started runs that witnessed it."""

    outcome: Literal["passed", "failed", "not-run"] = "not-run"
    runs: tuple[int, ...] = ()


@dataclass
class _Declarations:
    names: set[str] = field(default_factory=set)
    namespaces: set[str] = field(default_factory=set)
    nested: set[str] = field(default_factory=set)
    incomplete: bool = False


def _safe_name(value: Any) -> bool:
    return (type(value) is str and len(value) <= 96 and _TOOL_NAME.fullmatch(value) is not None
            and _CREDENTIAL_PREFIX.search(value) is None)


def _add_name(values: set[str], value: Any) -> bool:
    if not _safe_name(value):
        return False
    if len(values) == _MAX_NAMES and value not in values:
        return False
    values.add(value)
    return True


def _declaration_name(spec: Mapping[str, Any], prefix: str) -> str:
    kind = spec.get("type")
    if not isinstance(kind, str):
        return ""
    name = spec.get("name")
    if isinstance(name, str):
        return prefix + name
    # Nameless provider-hosted specs use the type as their identifier.
    if "name" in spec or kind in ("namespace", "function", "custom"):
        return ""
    return prefix + kind


def _code_mode_names(spec: Mapping[str, Any], parsed: _Declarations) -> None:
    description = spec.get("description")
    headings = _CODE_MODE_HEADING.finditer(description) if isinstance(description, str) else ()
    found = False
    for match in headings:
        found = True
        if not _add_name(parsed.nested, match[1]):
            parsed.incomplete = True
    if not found:
        parsed.incomplete = True


def _read_spec(spec: Any, parsed: _Declarations, prefix: str, depth: int) -> None:
    if not isinstance(spec, Mapping) or not _safe_name(name := _declaration_name(spec, prefix)):
        parsed.incomplete = True
        return
    if spec.get("type") == "namespace":
        if not _add_name(parsed.namespaces, name):
            parsed.incomplete = True
        _read_specs(spec.get("tools"), parsed, prefix=name + ".", depth=depth + 1)
    elif not _add_name(parsed.names, name):
        parsed.incomplete = True
    elif name == "functions.exec" and spec.get("type") == "custom":
        _code_mode_names(spec, parsed)


def _read_specs(specs: Any, parsed: _Declarations, *, prefix: str = "", depth: int = 0) -> None:
    if not isinstance(specs, list) or depth > 3:
        parsed.incomplete = True
        return
    for spec in specs:
        _read_spec(spec, parsed, prefix, depth)


def _turn_window(records: Sequence[Mapping[str, Any]], turn_id: str) -> tuple[int, int, bool]:
    if not isinstance(turn_id, str) or not turn_id:
        raise NativeSessionBoundaryError("tool observation requires a turn identity")
    starts = record_indices(records, "event_msg", "task_started")
    matches = [index for index in starts if records[index]["payload"].get("turn_id") == turn_id]
    if len(matches) != 1:
        raise NativeSessionBoundaryError("tool observation requires a singular turn start")
    start = matches[0]
    terminal = trusted_terminal_event(records, turn_id=turn_id)
    end = terminal["record_index"] if terminal is not None else len(records)
    if not start < end or any(start < index < end for index in starts):
        raise NativeSessionBoundaryError("tool observation has ambiguous turn bounds")
    return start + 1, end, terminal is not None


def _has_exact_context(records: Sequence[Mapping[str, Any]], start: int, end: int, turn_id: str) -> bool:
    contexts = []
    for index in record_indices(records, "turn_context"):
        payload = records[index].get("payload")
        if start <= index < end or (isinstance(payload, Mapping) and
                                    turn_id in (payload.get("turn_id"), payload.get("turnId"))):
            contexts.append((index, payload))
    if len(contexts) != 1:
        return False
    index, payload = contexts[0]
    return (start <= index < end and isinstance(payload, Mapping) and
            payload.get("turn_id") == turn_id and "turnId" not in payload)


def _registered_tools(records: Sequence[Mapping[str, Any]]) -> _Declarations:
    parsed = _Declarations()
    meta = record_indices(records, "session_meta")
    payload = records[meta[0]].get("payload") if len(meta) == 1 else None
    _read_specs(payload.get("dynamic_tools") if isinstance(payload, Mapping) else None, parsed)
    return parsed


def _world_state_names(payload: Mapping[str, Any], parsed: _Declarations) -> bool:
    state = payload.get("state")
    if not isinstance(state, Mapping) or type(payload.get("full")) is not bool:
        parsed.incomplete = True
        return False
    tools = state.get("top_level_tools")
    if not isinstance(tools, Mapping):
        # An incremental record can change unrelated state only.
        if payload["full"] or "top_level_tools" in state:
            parsed.incomplete = True
        return False
    for name, digest in tools.items():
        if not (isinstance(digest, str) and _DIGEST.fullmatch(digest) and _add_name(parsed.names, name)):
            parsed.incomplete = True
    return True


def _additional_names(payload: Mapping[str, Any], parsed: _Declarations) -> bool:
    if payload.get("role") != "developer" or not isinstance(payload.get("tools"), list):
        parsed.incomplete = True
        return False
    _read_specs(payload["tools"], parsed)
    return True


def _turn_matches(row: Mapping[str, Any], payload: Any, turn_id: str) -> bool:
    return isinstance(payload, Mapping) and all(
        source.get(key) in (None, turn_id) for source in (row, payload) for key in ("turn_id", "turnId")
    )


def _read_turn_declarations(records: Sequence[Mapping[str, Any]], turn_id: str
                            ) -> tuple[_Declarations, _Declarations, bool]:
    world = _Declarations()
    offered = _Declarations()
    observed = False
    for row in records:
        payload = row.get("payload")
        if row.get("type") == "world_state":
            if _turn_matches(row, payload, turn_id):
                observed = _world_state_names(payload, world) or observed
            else:
                world.incomplete = True
        elif row.get("type") == "response_item" and isinstance(payload, Mapping) and payload.get("type") == "additional_tools":
            if _turn_matches(row, payload, turn_id):
                observed = _additional_names(payload, offered) or observed
            else:
                offered.incomplete = True
    return world, offered, observed


def _world_tool_names(world: _Declarations, offered: _Declarations) -> set[str]:
    # The 0.171 rollout name map includes entries for namespace containers.
    parents = {name.rpartition(".")[0] for name in world.names}
    return world.names - offered.namespaces - parents


def _tool_observation(world: _Declarations, offered: _Declarations, registered: _Declarations,
                      expected_tools: Sequence[str], limitations: set[str]) -> WorkerToolObservation:
    expected = set(expected_tools)
    expected.update(name.replace(".", "__") for name in expected_tools)
    names = _world_tool_names(world, offered)
    unexpected = (names | offered.names | offered.nested | registered.names) - expected
    if world.incomplete or offered.incomplete:
        limitations.add("declarations-incomplete")
    if registered.incomplete:
        limitations.add("registration-unavailable")
    return WorkerToolObservation(tuple(sorted(names)), tuple(sorted(offered.names)), tuple(sorted(offered.nested)),
                                 tuple(sorted(registered.names)), tuple(sorted(unexpected)), tuple(sorted(limitations)))


def observe_worker_tools(records: Sequence[Mapping[str, Any]], *, turn_id: str,
                         expected_tools: Sequence[str] = _EXPECTED_TOOLS) -> WorkerToolObservation:
    """Project the original, identity-bound rollout for one acknowledged worker turn.

    The caller establishes source ownership and worker/session binding with the
    native boundary reader. Only declarations within a matching turn count.
    Registration is independent of that turn and remains a distinct source.
    """
    registered = _registered_tools(records)
    try:
        start, end, terminal = _turn_window(records, turn_id)
        if not _has_exact_context(records, start, end, turn_id):
            raise NativeSessionBoundaryError("tool observation requires an exact turn context")
    except NativeSessionBoundaryError:
        return _tool_observation(_Declarations(), _Declarations(), registered, expected_tools,
                                 {"turn-unbound", "declarations-unavailable"})
    world, offered, observed = _read_turn_declarations(records[start:end], turn_id)
    limitations = set() if terminal else {"terminal-unavailable"}
    if not observed:
        limitations.add("declarations-unavailable")
    return _tool_observation(world, offered, registered, expected_tools, limitations)


def _safe_run(value: Any, upper: int) -> bool:
    return type(value) is int and 1 <= value <= upper


def _outcome_record(value: OutcomeObservation, runs_consumed: int) -> dict[str, Any]:
    if not isinstance(value, OutcomeObservation) or value.outcome not in {"passed", "failed", "not-run"}:
        raise ValueError("qualification behavior outcome is invalid")
    if not all(_safe_run(run, runs_consumed) for run in value.runs):
        raise ValueError("qualification behavior references a run outside the consumed allowance")
    if bool(value.runs) != (value.outcome != "not-run"):
        raise ValueError("qualification behavior must cite started runs for an observed outcome")
    return {"outcome": value.outcome, "runs": sorted(set(value.runs))}


def _behavior_records(outcomes: Mapping[str, OutcomeObservation], runs_consumed: int) -> dict[str, Any]:
    if set(outcomes) - set(REQUIRED_BEHAVIORS):
        raise ValueError("qualification record has an unknown required behavior")
    records = {key: _outcome_record(outcomes.get(key, OutcomeObservation()), runs_consumed)
               for key in REQUIRED_BEHAVIORS}
    if set(records["n2_concurrency"]["runs"]) & set(records["n3_concurrency"]["runs"]):
        raise ValueError("N=2 and N=3 concurrency require separate started runs")
    return records


def _bounded_names(names: tuple[str, ...]) -> list[str]:
    return sorted({name for name in names if _safe_name(name)})[:_MAX_NAMES * 4]


def _worker_record(run: int, worker: int, value: WorkerToolObservation) -> dict[str, Any]:
    if not _safe_run(worker, 3) or not isinstance(value, WorkerToolObservation):
        raise ValueError("qualification record has an invalid worker tool observation")
    return {
        "run": run,
        "worker": worker,
        "rollout.world_state.top_level_tools": _bounded_names(value.world_state_tools),
        "rollout.additional_tools": _bounded_names(value.additional_tools),
        "rollout.additional_tools.functions.exec": _bounded_names(value.code_mode_tools),
        "rollout.session_meta.dynamic_tools": _bounded_names(value.registered_tools),
        "unexpected": _bounded_names(value.unexpected),
        "limitations": [_TOOL_LIMITATIONS[key] for key in sorted(set(value.limitations)) if key in _TOOL_LIMITATIONS],
    }


def _worker_records(worker_tools: Mapping[int, Mapping[int, WorkerToolObservation]],
                    runs_consumed: int) -> list[dict[str, Any]]:
    records = []
    for run, workers in worker_tools.items():
        if not _safe_run(run, runs_consumed):
            raise ValueError("qualification tool observation references a run outside the consumed allowance")
        records.extend(_worker_record(run, worker, value) for worker, value in workers.items())
    return sorted(records, key=lambda item: (item["run"], item["worker"]))


def _record_outcome(behaviors: Mapping[str, Any], runs_consumed: int) -> str:
    outcomes = {entry["outcome"] for entry in behaviors.values()}
    if "failed" in outcomes:
        return "failed"
    if "not-run" in outcomes:
        return "incomplete" if runs_consumed else "not-run"
    return "passed"


def _catalog_records(catalog_modes: Mapping[int, CatalogMode], runs_consumed: int) -> list[dict[str, Any]]:
    if not all(_safe_run(run, runs_consumed) and mode in ("trimmed", "stock-fallback")
               for run, mode in catalog_modes.items()):
        raise ValueError("qualification record has an invalid model catalog observation")
    return [{"run": run, "mode": mode} for run, mode in sorted(catalog_modes.items())]


def build_pass_record(*, cwo_version: str, minimum_codex_version: str, date: Date,
                      runs_consumed: int, run_cap: int, outcomes: Mapping[str, OutcomeObservation],
                      worker_tools: Mapping[int, Mapping[int, WorkerToolObservation]],
                      catalog_modes: Mapping[int, CatalogMode] | None = None) -> dict[str, Any]:
    """Summarize the stage's original outcomes, with catalog evidence beside them.

    The controller owns the durable allowance, cohort admission and result
    attestation. This formatter grants no authority and does not infer an
    outcome from configured tools or the names seen in a rollout.
    """
    if not all(isinstance(value, str) and _VERSION.fullmatch(value) for value in (cwo_version, minimum_codex_version)):
        raise ValueError("qualification record requires CWO and minimum Codex versions")
    if type(date) is not Date:
        raise ValueError("qualification record requires an exact qualification date")
    if not _safe_run(run_cap, CAMPAIGN_MAX_START_CAP) or type(runs_consumed) is not int or not 0 <= runs_consumed <= run_cap:
        raise ValueError("qualification record has an invalid run count or cap")
    behaviors = _behavior_records(outcomes, runs_consumed)
    return {
        "qualification": "contained-pool",
        "cwo_version": cwo_version,
        "minimum_codex_version": minimum_codex_version,
        "model": QUALIFICATION_MODEL,
        "effort": QUALIFICATION_EFFORT,
        "tier": QUALIFICATION_TIER,
        "date": date.isoformat(),
        "runs_consumed": runs_consumed,
        "run_cap": run_cap,
        "outcome": _record_outcome(behaviors, runs_consumed),
        "behaviors": behaviors,
        "tool_lists": _worker_records(worker_tools, runs_consumed),
        "model_catalog": _catalog_records(catalog_modes or {}, runs_consumed),
        "limitations": [
            "Qualification covers the witnessed disposable cohorts and behaviors.",
            "Login-path denial checks the mounted read-only deny rule and the active named profile. "
            "No login read was attempted.",
            "Rollout declarations cover the observations in the worker turn. Other requests, "
            "retained context, deferred tools and unlisted workers have no complete inventory here. "
            "Empty lists can reflect empty declarations or missing telemetry.",
            "Session metadata describes dynamic registration only. Tool declarations are informational.",
        ],
    }
