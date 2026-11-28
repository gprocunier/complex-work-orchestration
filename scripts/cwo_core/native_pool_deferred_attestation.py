"""Join protected pool allocation intent to original transport observations.

This is evidence validation for a parent that already selected the factory and
verified original stdio and session JSONL. The records returned here confer no
authority to dispatch, release an effect, or assert an effective tool catalog.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass
import math
from pathlib import Path
import re
from time import monotonic
from typing import TYPE_CHECKING, Any, Mapping

from .native_tool_isolation import CONTAINED_POOL_WRITER as QUALIFICATION_TOOL
from .worker_patch import MAX_WORKER_DIFF_BYTES

if TYPE_CHECKING:
    from .native_pool_transaction import TransactionJournal

_EVIDENCE_TOKEN = object()


class DeferredAttestationError(ValueError):
    """Protected deferred worker evidence was missing or inconsistent."""


@dataclass(frozen=True, slots=True)
class ObservedExchangeDigest:
    request_id: int
    request_sha256: str
    response_sha256: str


@dataclass(frozen=True, slots=True)
class ProvisionalWorkerStartup:
    plan_sha256: str
    allocation_id: str
    allocation_intent_event_sha256: str
    child_id: str
    worktree_identity_sha256: str
    session_id: str
    session_path: str
    connection_epoch_sha256: str
    owner_identity_sha256: str
    model: str
    effort: str
    profile: str
    prompt_sha256: str
    startup_exchange: ObservedExchangeDigest
    startup_rollout_sha256: str | None
    startup_source_identity_sha256: str | None
    deadline: float
    issuer: InitVar[object]

    def __post_init__(self, issuer: object) -> None:
        _require(issuer is _EVIDENCE_TOKEN, "startup-evidence-construction-refused")


@dataclass(frozen=True, slots=True)
class DeferredWorkerTurnEvidence:
    startup: ProvisionalWorkerStartup
    turn_id: str
    turn_exchange: ObservedExchangeDigest
    request_id: int | str
    request_sha256: str
    session_source_identity_sha256: str
    boundary_sha256: str
    issuer: InitVar[object]

    def __post_init__(self, issuer: object) -> None:
        _require(issuer is _EVIDENCE_TOKEN, "turn-evidence-construction-refused")


def require_deferred_attestation(condition: bool, reason: str) -> None:
    if not condition:
        raise DeferredAttestationError("pool-deferred-" + reason)


def require_deferred_deadline(deadline: float, *, now: float) -> None:
    _require(type(deadline) is float and math.isfinite(deadline) and now < deadline, "deadline-expired")


_require = require_deferred_attestation


def _digest(value: Any, reason: str) -> str:
    _require(type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None, reason)
    return value


def _deadline(deadline: float) -> None:
    require_deferred_deadline(deadline, now=monotonic())


def _record(value: Any, reason: str) -> dict[str, Any]:
    _require(type(value) is dict, reason)
    return value


def _text(value: Any, reason: str) -> str:
    _require(type(value) is str and bool(value.strip()), reason)
    return value


def _exchange(value: Mapping[str, Any]) -> ObservedExchangeDigest:
    request_id = value.get("request_id")
    _require(type(request_id) is int and request_id > 0, "request-id-invalid")
    return ObservedExchangeDigest(request_id, _digest(value.get("request_sha256"), "request-digest-invalid"),
                                  _digest(value.get("response_sha256"), "response-digest-invalid"))


def _startup_rollout(readback: Mapping[str, Any]) -> tuple[str | None, str | None]:
    fields = "session_sha256", "session_source_identity_sha256"
    _require(all(field in readback for field in fields), "startup-rollout-readback-required")
    prefix, identity = (readback[field] for field in fields)
    if prefix is None and identity is None:
        return None, None
    return _digest(prefix, "startup-rollout-prefix-invalid"), _digest(identity, "startup-rollout-source-invalid")


def verify_deferred_startup(
    plan: Mapping[str, Any], *, journal: TransactionJournal, child_id: str, approved_plan_sha256: str,
    trusted_factories: Mapping[str, str], readback: Mapping[str, Any], worktree: Path,
    session_path: Path, connection_epoch_sha256: str, effort: str, profile: str, prompt_sha256: str,
    deadline: float,
) -> ProvisionalWorkerStartup:
    """Capture startup and any original rollout prefix preceding the first turn.

    The caller supplies the registry and observation from its protected Python
    context. The factory loader still owns source verification and execution.
    """
    from .native_pool_deferred_context import QUALIFICATION_EFFORT, QUALIFICATION_MODEL, QUALIFICATION_PROFILE, QUALIFICATION_TIER
    from .native_pool_transaction import PLAN_VERSION, require_current_worker_allocation_intent, validate_transaction_plan

    _deadline(deadline)
    _require(not validate_transaction_plan(plan) and plan["version"] == PLAN_VERSION
             and plan["prelude_session_count"] == 0, "ordinary-plan-required")
    _require(plan["plan_sha256"] == approved_plan_sha256, "plan-unapproved")
    _require(plan["selected_model"] == QUALIFICATION_MODEL and effort == QUALIFICATION_EFFORT
             and profile == QUALIFICATION_PROFILE,
             "qualification-model-selection-mismatch")
    _require(trusted_factories.get(plan["runtime_adapter_path"]) == plan["runtime_adapter_sha256"], "factory-unapproved")
    child, intent = require_current_worker_allocation_intent(plan, journal, child_id)
    _require(worktree.is_absolute() and session_path.is_absolute() and session_path.suffix == ".jsonl",
             "startup-path-invalid")
    selections = {"model": QUALIFICATION_MODEL, "effort": QUALIFICATION_EFFORT, "service_tier": QUALIFICATION_TIER,
                  "profile": _text(profile, "profile-invalid"), "worktree": str(worktree),
                  "session_path": str(session_path), "epoch": _digest(connection_epoch_sha256, "epoch-invalid")}
    _require(all(readback.get(key) == selected for key, selected in selections.items()), "startup-selection-mismatch")
    _require(readback.get("worktree_identity_sha256") == child["worktree_identity_sha256"], "startup-worktree-mismatch")
    owner_identity = _digest(readback.get("owner_identity_sha256"), "startup-owner-invalid")
    rollout_sha256, source_identity = _startup_rollout(readback)
    session_id = _text(readback.get("thread_id"), "startup-thread-invalid")
    wire = _exchange(_record(readback.get("thread_start"), "startup-exchange-missing"))
    _deadline(deadline)
    return ProvisionalWorkerStartup(
        plan_sha256=approved_plan_sha256,
        allocation_id=intent["details"]["allocation_id"],
        allocation_intent_event_sha256=intent["event_sha256"],
        child_id=child_id,
        worktree_identity_sha256=child["worktree_identity_sha256"],
        session_id=session_id,
        session_path=str(session_path),
        connection_epoch_sha256=connection_epoch_sha256,
        owner_identity_sha256=owner_identity,
        model=selections["model"],
        effort=effort,
        profile=profile,
        prompt_sha256=_digest(prompt_sha256, "prompt-digest-invalid"),
        startup_exchange=wire,
        startup_rollout_sha256=rollout_sha256,
        startup_source_identity_sha256=source_identity,
        deadline=deadline,
        issuer=_EVIDENCE_TOKEN,
    )


def attest_deferred_turn(
    startup: ProvisionalWorkerStartup, *, turn_ack: Mapping[str, Any], evidence: Mapping[str, Any],
    pending_callback: Mapping[str, Any], patch_mode: bool = False,
) -> DeferredWorkerTurnEvidence:
    """Join transport-verified JSONL to the protected controller's recorded turn acknowledgement."""
    _require(type(startup) is ProvisionalWorkerStartup, "provisional-startup-required")
    _deadline(startup.deadline)
    turn_id = _text(turn_ack.get("turn_id"), "turn-ack-id-invalid")
    _require(turn_ack.get("child_id") == startup.child_id and turn_ack.get("thread_id") == startup.session_id,
             "turn-ack-mismatch")
    _require(evidence.get("thread_id") == startup.session_id and evidence.get("turn_id") == turn_id
             and evidence.get("epoch") == startup.connection_epoch_sha256
             and evidence.get("owner_identity_sha256") == startup.owner_identity_sha256
             and evidence.get("session_path") == startup.session_path, "turn-observation-mismatch")
    request_id, request_digest = _pending_callback(pending_callback, startup, turn_id, patch_mode=patch_mode)
    provenance = _record(evidence.get("startup_to_turn"), "turn-provenance-missing")
    wire_start = _exchange(_record(provenance.get("thread_start"), "startup-exchange-missing"))
    _require(wire_start == startup.startup_exchange, "startup-exchange-changed")
    wire_turn = _record(provenance.get("turn_start"), "turn-exchange-missing")
    turn_exchange = _exchange(wire_turn)
    _require(turn_exchange.request_id > wire_start.request_id and wire_turn.get("turn_id") == turn_id
             and wire_turn.get("prompt_sha256") == startup.prompt_sha256, "turn-exchange-mismatch")
    expected_context = {"turn_id": turn_id, "model": startup.model, "effort": startup.effort}
    _require(provenance.get("turn_context") == expected_context, "turn-context-mismatch")
    boundary = _record(evidence.get("terminal_boundary"), "rollout-boundary-missing")
    index, count = provenance.get("turn_context_index"), boundary.get("record_count")
    _require(type(index) is int and type(count) is int and 0 < index < count, "turn-context-boundary-mismatch")
    source_identity = _digest(boundary.get("source_identity_sha256"), "rollout-source-missing")
    _require(provenance.get("startup_rollout_prefix_sha256") == startup.startup_rollout_sha256
             and startup.startup_source_identity_sha256 in (None, source_identity), "startup-rollout-prefix-drift")
    _deadline(startup.deadline)
    return DeferredWorkerTurnEvidence(
        startup=startup,
        turn_id=turn_id,
        turn_exchange=turn_exchange,
        request_id=request_id,
        request_sha256=request_digest,
        session_source_identity_sha256=source_identity,
        boundary_sha256=_digest(boundary.get("boundary_sha256"), "rollout-boundary-missing"),
        issuer=_EVIDENCE_TOKEN,
    )


def writer_arguments_match(arguments: Any, *, patch_mode: bool = False) -> bool:
    """Check the exact callback argument shape and UTF-8 budget for the retained writer mode."""
    if type(arguments) is not dict or type(patch_mode) is not bool:
        return False
    if not patch_mode:
        return not arguments
    diff = arguments.get("diff")
    if arguments.keys() != {"diff"} or type(diff) is not str or not 0 < len(diff) <= MAX_WORKER_DIFF_BYTES:
        return False
    try:
        return len(diff.encode("utf-8")) <= MAX_WORKER_DIFF_BYTES
    except UnicodeEncodeError:
        return False


def _pending_callback(value: Mapping[str, Any], startup: ProvisionalWorkerStartup, turn_id: str,
                      *, patch_mode: bool) -> tuple[int | str, str]:
    request_id = value.get("request_id")
    _require(type(request_id) in (int, str) and request_id != "", "pending-callback-id-invalid")
    expected = {"thread_id": startup.session_id, "turn_id": turn_id, "epoch": startup.connection_epoch_sha256,
                "owner_identity_sha256": startup.owner_identity_sha256, "tool": QUALIFICATION_TOOL}
    _require(all(value.get(field) == selected for field, selected in expected.items())
             and writer_arguments_match(value.get("arguments"), patch_mode=patch_mode),
             "pending-callback-binding-mismatch")
    return request_id, _digest(value.get("request_sha256"), "pending-callback-digest-invalid")
