"""Deterministic scheduling and aggregate accounting for native worker pools."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from .native_pool_contracts import canonical_sha256, zero_token_usage, zero_usage


NUMERIC_USAGE_FIELDS = (
    "tool_calls",
    "runtime_seconds",
    "compactions",
    "full_suite_runs",
    "mutations",
)
TOKEN_COUNTER_FIELDS = ("input", "cached_input", "output", "reasoning", "total")
USAGE_FIELDS = {*NUMERIC_USAGE_FIELDS, "tokens"}
TOKEN_FIELDS = {"availability", *TOKEN_COUNTER_FIELDS, "unavailable_reason"}


class PoolSchedulingError(ValueError):
    """Raised when deterministic scheduling evidence is malformed."""


class PoolAccountingError(ValueError):
    """Raised when cumulative usage cannot be reconciled safely."""


@dataclass(frozen=True)
class SchedulerSelection:
    child_id: str
    ordinal: int
    deadline_ns: int
    next_cursor: int


@dataclass(frozen=True)
class UsageObservation:
    child_id: str
    child_state_sha256: str
    decision_sequence: int
    delta: dict[str, Any]
    aggregate: dict[str, Any]


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PoolAccountingError(f"{field}-must-be-nonnegative-integer")
    return value


def _require_sha256(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PoolAccountingError(f"{field}-must-be-lowercase-sha256")
    return value


def normalize_usage(value: Any) -> dict[str, Any]:
    """Return one strict cumulative-usage object or fail closed."""
    if not isinstance(value, Mapping) or set(value) != USAGE_FIELDS:
        raise PoolAccountingError("usage-fields-invalid")
    result: dict[str, Any] = {
        field: _nonnegative_int(value.get(field), f"usage-{field.replace('_', '-')}")
        for field in NUMERIC_USAGE_FIELDS
    }
    tokens = value.get("tokens")
    if not isinstance(tokens, Mapping) or set(tokens) != TOKEN_FIELDS:
        raise PoolAccountingError("token-usage-fields-invalid")
    availability = tokens.get("availability")
    if availability == "available":
        normalized_tokens = {
            field: _nonnegative_int(tokens.get(field), f"tokens-{field.replace('_', '-')}")
            for field in TOKEN_COUNTER_FIELDS
        }
        if tokens.get("unavailable_reason") is not None:
            raise PoolAccountingError("available-token-usage-has-unavailable-reason")
        if normalized_tokens["total"] != sum(
            normalized_tokens[field] for field in TOKEN_COUNTER_FIELDS if field != "total"
        ):
            raise PoolAccountingError("token-total-mismatch")
        result["tokens"] = {
            "availability": "available",
            **normalized_tokens,
            "unavailable_reason": None,
        }
    elif availability == "unavailable":
        if any(tokens.get(field) is not None for field in TOKEN_COUNTER_FIELDS):
            raise PoolAccountingError("unavailable-token-usage-has-counters")
        reason = tokens.get("unavailable_reason")
        if not isinstance(reason, str) or not reason.strip():
            raise PoolAccountingError("unavailable-token-usage-missing-reason")
        result["tokens"] = {
            "availability": "unavailable",
            **{field: None for field in TOKEN_COUNTER_FIELDS},
            "unavailable_reason": reason,
        }
    else:
        raise PoolAccountingError("token-availability-invalid")
    return result


def usage_delta(previous: Any, current: Any) -> dict[str, Any]:
    """Compute a monotonic delta without inventing unavailable token values."""
    before = normalize_usage(previous)
    after = normalize_usage(current)
    delta = zero_usage()
    for field in NUMERIC_USAGE_FIELDS:
        if after[field] < before[field]:
            raise PoolAccountingError(f"cumulative-{field.replace('_', '-')}-reset")
        delta[field] = after[field] - before[field]

    before_tokens = before["tokens"]
    after_tokens = after["tokens"]
    if before_tokens["availability"] != after_tokens["availability"]:
        raise PoolAccountingError("token-availability-changed")
    if after_tokens["availability"] == "available":
        counters: dict[str, int] = {}
        for field in TOKEN_COUNTER_FIELDS:
            if after_tokens[field] < before_tokens[field]:
                raise PoolAccountingError(f"cumulative-token-{field.replace('_', '-')}-reset")
            counters[field] = after_tokens[field] - before_tokens[field]
        delta["tokens"] = {
            "availability": "available",
            **counters,
            "unavailable_reason": None,
        }
    else:
        delta["tokens"] = zero_token_usage()
    return delta


def sum_cumulative_usage(values: Iterable[Any]) -> dict[str, Any]:
    """Sum authoritative child totals using the frozen token-availability rule."""
    normalized = [normalize_usage(value) for value in values]
    if not normalized:
        return zero_usage()
    result = zero_usage()
    for field in NUMERIC_USAGE_FIELDS:
        result[field] = sum(value[field] for value in normalized)
    if all(value["tokens"]["availability"] == "available" for value in normalized):
        counters = {
            field: sum(value["tokens"][field] for value in normalized)
            for field in TOKEN_COUNTER_FIELDS
        }
        result["tokens"] = {
            "availability": "available",
            **counters,
            "unavailable_reason": None,
        }
    return result


def exhausted_budget(aggregate: Any, budget: Any) -> list[str]:
    """Return every hard budget dimension exceeded by authoritative totals."""
    usage = normalize_usage(aggregate)
    if not isinstance(budget, Mapping) or set(budget) != set(NUMERIC_USAGE_FIELDS):
        raise PoolAccountingError("aggregate-hard-budget-fields-invalid")
    reasons: list[str] = []
    for field in NUMERIC_USAGE_FIELDS:
        ceiling = _nonnegative_int(budget.get(field), f"budget-{field.replace('_', '-')}")
        if usage[field] > ceiling:
            reasons.append(f"aggregate-{field.replace('_', '-')}-exhausted")
    return reasons


class AggregateUsageLedger:
    """Exactly-once cumulative observation ledger for a fixed child cohort."""

    def __init__(
        self,
        child_ids: Sequence[str],
        *,
        initial_usage: Mapping[str, Any] | None = None,
    ) -> None:
        ids = tuple(child_ids)
        if not ids or any(not isinstance(child_id, str) or not child_id for child_id in ids):
            raise PoolAccountingError("child-ids-invalid")
        if len(ids) != len(set(ids)):
            raise PoolAccountingError("duplicate-child-id")
        self.child_ids = ids
        baseline = normalize_usage(initial_usage or zero_usage())
        self._latest = {child_id: normalize_usage(baseline) for child_id in ids}
        self._last_state_hash: dict[str, str | None] = {child_id: None for child_id in ids}
        self._seen: set[tuple[str, str, int]] = set()

    @property
    def aggregate(self) -> dict[str, Any]:
        return sum_cumulative_usage(self._latest[child_id] for child_id in self.child_ids)

    def latest_for(self, child_id: str) -> dict[str, Any]:
        if child_id not in self._latest:
            raise PoolAccountingError("unknown-child-id")
        return normalize_usage(self._latest[child_id])

    def observe(
        self,
        *,
        child_id: str,
        child_state_sha256: str,
        decision_sequence: int,
        cumulative_usage: Any,
    ) -> UsageObservation:
        if child_id not in self._latest:
            raise PoolAccountingError("unknown-child-id")
        state_hash = _require_sha256(child_state_sha256, "child-state-sha256")
        sequence = _nonnegative_int(decision_sequence, "decision-sequence")
        key = (child_id, state_hash, sequence)
        if key in self._seen:
            raise PoolAccountingError("usage-observation-replay")
        current = normalize_usage(cumulative_usage)
        delta = usage_delta(self._latest[child_id], current)
        self._latest[child_id] = current
        self._last_state_hash[child_id] = state_hash
        self._seen.add(key)
        return UsageObservation(
            child_id=child_id,
            child_state_sha256=state_hash,
            decision_sequence=sequence,
            delta=delta,
            aggregate=self.aggregate,
        )

    def reconcile(self, expected: Any) -> None:
        if self.aggregate != normalize_usage(expected):
            raise PoolAccountingError("aggregate-reconciliation-failed")


def select_earliest_deadline(
    children: Sequence[Mapping[str, Any]],
    *,
    cursor: int,
) -> SchedulerSelection | None:
    """Select the earliest deadline and rotate equal-deadline ties persistently."""
    if not children:
        return None
    if isinstance(cursor, bool) or not isinstance(cursor, int) or not 0 <= cursor < len(children):
        raise PoolSchedulingError("scheduler-cursor-out-of-range")
    candidates: list[tuple[int, int, str]] = []
    for ordinal, child in enumerate(children):
        child_id = child.get("child_id")
        deadline = child.get("next_deadline_ns")
        if not isinstance(child_id, str) or not child_id:
            raise PoolSchedulingError("child-id-invalid")
        if deadline is None:
            continue
        if isinstance(deadline, bool) or not isinstance(deadline, int) or deadline < 0:
            raise PoolSchedulingError("child-deadline-invalid")
        candidates.append((deadline, ordinal, child_id))
    if not candidates:
        return None
    earliest = min(deadline for deadline, _, _ in candidates)
    tied = {ordinal: child_id for deadline, ordinal, child_id in candidates if deadline == earliest}
    selected_ordinal = next(
        ordinal
        for ordinal in ((*range(cursor, len(children)), *range(0, cursor)))
        if ordinal in tied
    )
    return SchedulerSelection(
        child_id=tied[selected_ordinal],
        ordinal=selected_ordinal,
        deadline_ns=earliest,
        next_cursor=(selected_ordinal + 1) % len(children),
    )


def peer_deadline_guard(
    children: Sequence[Mapping[str, Any]],
    *,
    cursor: int,
    proposed_child_id: str,
    now_ns: int,
    certified_callback_ms: float,
    certified_scheduler_overhead_ms: float = 0.0,
) -> SchedulerSelection | None:
    """Choose a peer first when one would cross deadline during a lifecycle call."""
    if isinstance(now_ns, bool) or not isinstance(now_ns, int) or now_ns < 0:
        raise PoolSchedulingError("monotonic-time-invalid")
    if isinstance(certified_callback_ms, bool) or not isinstance(certified_callback_ms, (int, float)):
        raise PoolSchedulingError("certified-callback-latency-invalid")
    if certified_callback_ms < 0:
        raise PoolSchedulingError("certified-callback-latency-invalid")
    if (
        isinstance(certified_scheduler_overhead_ms, bool)
        or not isinstance(certified_scheduler_overhead_ms, (int, float))
        or certified_scheduler_overhead_ms < 0
    ):
        raise PoolSchedulingError("certified-scheduler-overhead-invalid")
    horizon = now_ns + int(
        (certified_callback_ms + certified_scheduler_overhead_ms) * 1_000_000
    )
    peers = [
        child
        for child in children
        if child.get("child_id") != proposed_child_id
        and child.get("next_deadline_ns") is not None
        and child.get("next_deadline_ns") <= horizon
    ]
    if not peers:
        return None
    eligible_ids = {child.get("child_id") for child in peers}
    selection = select_earliest_deadline(children, cursor=cursor)
    if selection is not None and selection.child_id in eligible_ids:
        return selection
    ordered = [child for child in children if child.get("child_id") in eligible_ids]
    fallback = select_earliest_deadline(ordered, cursor=0)
    if fallback is None:
        return None
    original_ordinal = next(
        index for index, child in enumerate(children) if child.get("child_id") == fallback.child_id
    )
    return SchedulerSelection(
        child_id=fallback.child_id,
        ordinal=original_ordinal,
        deadline_ns=fallback.deadline_ns,
        next_cursor=(original_ordinal + 1) % len(children),
    )


def wait_seconds(now_ns: int, deadline_ns: int | None) -> float:
    if deadline_ns is None:
        return 0.0
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in (now_ns, deadline_ns)):
        raise PoolSchedulingError("wait-deadline-invalid")
    return max(0.0, (deadline_ns - now_ns) / 1_000_000_000)


def mutation_evidence_sha256(value: Mapping[str, Any]) -> str:
    fields = ("integration_root_clean", "shared_read_only_clean", "child_worktrees_clean")
    if set(value) != {*fields, "evidence_sha256"}:
        raise PoolSchedulingError("mutation-evidence-fields-invalid")
    booleans = {field: value.get(field) for field in fields}
    if any(not isinstance(item, bool) for item in booleans.values()):
        raise PoolSchedulingError("mutation-evidence-values-invalid")
    expected = canonical_sha256(booleans)
    if value.get("evidence_sha256") != expected:
        raise PoolSchedulingError("mutation-evidence-sha256-mismatch")
    return expected
