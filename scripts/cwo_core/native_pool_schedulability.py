"""Pure schedulability proofs for cooperative native worker pools."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping


SCHEDULABILITY_PROOF_TYPE = "cwo-native-pool-schedulability-proof"
SCHEDULABILITY_PROOF_VERSION = 1
SCHEDULABILITY_FORMULA = (
    "lifecycle_max_ms + requested_workers * check_max_ms + "
    "scheduler_overhead_ms <= poll_interval_ms"
)


class PoolSchedulabilityError(ValueError):
    """Raised when certified scheduling inputs cannot produce a proof."""


def _decimal_number(
    value: Any,
    field: str,
    *,
    strictly_positive: bool = False,
) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PoolSchedulabilityError(f"{field}-must-be-finite-number")
    try:
        normalized = Decimal(str(value))
    except InvalidOperation as error:
        raise PoolSchedulabilityError(f"{field}-must-be-finite-number") from error
    if not normalized.is_finite():
        raise PoolSchedulabilityError(f"{field}-must-be-finite-number")
    if normalized < 0 or (strictly_positive and normalized == 0):
        qualifier = "positive" if strictly_positive else "nonnegative"
        raise PoolSchedulabilityError(f"{field}-must-be-{qualifier}")
    return normalized


def _plain_number(value: Decimal) -> int | float:
    integral = value.to_integral_value()
    return int(integral) if value == integral else float(value)


@dataclass(frozen=True, slots=True)
class SchedulingBudgetProof:
    """Machine-readable proof for one certified cooperative pool size."""

    requested_workers: int
    certified_callback_max_ms: dict[str, int | float]
    lifecycle_max_ms: int | float
    check_max_ms: int | float
    scheduler_overhead_ms: int | float
    poll_interval_ms: int | float
    total_demand_ms: int | float
    slack_ms: int | float
    accepted: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "proof_type": SCHEDULABILITY_PROOF_TYPE,
            "version": SCHEDULABILITY_PROOF_VERSION,
            "formula": SCHEDULABILITY_FORMULA,
            "inputs": {
                "requested_workers": self.requested_workers,
                "certified_callback_max_ms": dict(
                    self.certified_callback_max_ms
                ),
                "scheduler_overhead_ms": self.scheduler_overhead_ms,
                "poll_interval_ms": self.poll_interval_ms,
            },
            "lifecycle_max_ms": self.lifecycle_max_ms,
            "check_max_ms": self.check_max_ms,
            "total_demand_ms": self.total_demand_ms,
            "slack_ms": self.slack_ms,
            "accepted": self.accepted,
        }


def scheduling_budget_proof(
    *,
    requested_workers: int,
    certified_callback_max_ms: Mapping[str, Any],
    certified_scheduler_overhead_ms: int | float,
    poll_interval_ms: int | float,
) -> SchedulingBudgetProof:
    """Prove the exact N-worker cooperative scheduling inequality."""

    if (
        isinstance(requested_workers, bool)
        or not isinstance(requested_workers, int)
        or requested_workers < 1
    ):
        raise PoolSchedulabilityError(
            "requested-workers-must-be-positive-integer"
        )
    if (
        not isinstance(certified_callback_max_ms, Mapping)
        or not certified_callback_max_ms
        or "check" not in certified_callback_max_ms
    ):
        raise PoolSchedulabilityError(
            "certified-callback-max-ms-must-contain-check"
        )

    normalized_callbacks: dict[str, Decimal] = {}
    for name, value in certified_callback_max_ms.items():
        if not isinstance(name, str) or not name:
            raise PoolSchedulabilityError(
                "certified-callback-name-must-be-nonempty-string"
            )
        normalized_callbacks[name] = _decimal_number(
            value,
            f"certified-callback-{name}-ms",
        )
    overhead = _decimal_number(
        certified_scheduler_overhead_ms,
        "certified-scheduler-overhead-ms",
    )
    poll_interval = _decimal_number(
        poll_interval_ms,
        "poll-interval-ms",
        strictly_positive=True,
    )
    lifecycle_max = max(normalized_callbacks.values())
    check_max = normalized_callbacks["check"]
    total_demand = (
        lifecycle_max
        + Decimal(requested_workers) * check_max
        + overhead
    )
    slack = poll_interval - total_demand
    return SchedulingBudgetProof(
        requested_workers=requested_workers,
        certified_callback_max_ms={
            name: _plain_number(value)
            for name, value in sorted(normalized_callbacks.items())
        },
        lifecycle_max_ms=_plain_number(lifecycle_max),
        check_max_ms=_plain_number(check_max),
        scheduler_overhead_ms=_plain_number(overhead),
        poll_interval_ms=_plain_number(poll_interval),
        total_demand_ms=_plain_number(total_demand),
        slack_ms=_plain_number(slack),
        accepted=slack >= 0,
    )


def validate_slack_warning_fraction(value: Any) -> float:
    """Return a strict policy fraction in the interval ``(0, 1]``."""

    fraction = _decimal_number(
        value,
        "slack-warning-fraction",
        strictly_positive=True,
    )
    if fraction > 1:
        raise PoolSchedulabilityError(
            "slack-warning-fraction-must-not-exceed-one"
        )
    return float(fraction)


def latency_consumes_slack_fraction(
    proof: SchedulingBudgetProof,
    *,
    observed_latency_ms: int | float,
    warning_fraction: int | float,
) -> bool:
    """Flag advisory pressure without changing the certified proof."""

    if not isinstance(proof, SchedulingBudgetProof):
        raise PoolSchedulabilityError("scheduling-proof-required")
    observed = _decimal_number(
        observed_latency_ms,
        "observed-latency-ms",
    )
    fraction = Decimal(str(validate_slack_warning_fraction(warning_fraction)))
    slack = Decimal(str(proof.slack_ms))
    if slack <= 0:
        return True
    return observed >= slack * fraction
