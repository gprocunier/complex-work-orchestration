"""Native callback measurement, certification and source identity."""

from __future__ import annotations

import datetime as dt
import json
import math
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from cwo_core.native_canary_contracts import canonical_sha256 as domain_sha256
from cwo_core.native_pool_capacity import load_pool_capacity
from cwo_core.native_pool_contracts import (
    CAPABILITY_CERTIFICATION_ENVELOPE,
    CAPABILITY_CERTIFICATION_VERSION,
    CAPABILITY_OBSERVATION_AUTHORITY,
    CAPABILITY_RESPONSE_TIME_EQUATION,
    CAPABILITY_SCHEDULER_MODEL,
    CAPABILITY_SLACK_WARNING_FRACTION,
    CERTIFIED_CALLBACK_MAX_MS,
    CERTIFIED_SCHEDULER_OVERHEAD_MS,
    callback_certification_policy_sha256,
)
from cwo_core.native_pool_schedulability import (
    PoolSchedulabilityError,
    scheduling_budget_proof,
)
from cwo_core.supervision.transport.app_server import sha256_bytes
from cwo_core.supervision.transport.errors import AppServerError

ROOT = Path(__file__).resolve().parents[3]


PROVISIONAL_TERMINAL_GRACE_SECONDS = 5.0


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(value: dt.datetime | None = None) -> str:
    return (value or utc_now()).isoformat().replace("+00:00", "Z")


def percentile(values: list[float], ratio: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("capability-stat-samples-missing")
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * ratio) - 1))
    return ordered[index]


def stats(values: list[float]) -> dict[str, float]:
    return {
        "p50_ms": round(percentile(values, 0.50), 3),
        "p90_ms": round(percentile(values, 0.90), 3),
        "p99_ms": round(percentile(values, 0.99), 3),
        "max_ms": round(max(values), 3),
    }


def callback_certification_policy() -> dict[str, Any]:
    try:
        document = json.loads(
            (ROOT / "policy" / "native-worker-execution.yaml").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise AppServerError("callback-certification-policy-unreadable") from exc
    pool = document.get("native_supervision_pool") if isinstance(document, Mapping) else None
    certification = pool.get("callback_certification") if isinstance(pool, Mapping) else None
    expected = {
        "version": CAPABILITY_CERTIFICATION_VERSION,
        "envelope": CAPABILITY_CERTIFICATION_ENVELOPE,
        "scheduler_model": CAPABILITY_SCHEDULER_MODEL,
        "response_time_equation": CAPABILITY_RESPONSE_TIME_EQUATION,
        "observation_authority": CAPABILITY_OBSERVATION_AUTHORITY,
        "certified_callback_max_ms": CERTIFIED_CALLBACK_MAX_MS,
        "certified_scheduler_overhead_ms": CERTIFIED_SCHEDULER_OVERHEAD_MS,
        "slack_warning_fraction": CAPABILITY_SLACK_WARNING_FRACTION,
    }
    if not isinstance(certification, Mapping) or dict(certification) != expected:
        raise AppServerError("callback-certification-policy-invalid")
    limits = load_pool_capacity(document)
    try:
        proof = scheduling_budget_proof(
            requested_workers=limits.hard_max_active_workers,
            certified_callback_max_ms=CERTIFIED_CALLBACK_MAX_MS,
            certified_scheduler_overhead_ms=(
                CERTIFIED_SCHEDULER_OVERHEAD_MS
            ),
            poll_interval_ms=pool.get("scheduler", {}).get(
                "poll_interval_ms"
            ),
        )
    except PoolSchedulabilityError as error:
        raise AppServerError(
            "callback-certification-schedulability-input-invalid"
        ) from error
    if not proof.accepted:
        raise AppServerError("callback-certification-hard-cap-unschedulable")
    return dict(certification)


# Bind shared timing and transport and the current calibration implementation.
ADAPTER_IMPLEMENTATION_PATHS = (
    "scripts/registered_pool_qualification_capability.py",
    "scripts/registered_pool_qualification_calibration.py",
    "scripts/registered_pool_qualification.py",
    "scripts/registered_pool_ordinary_runtime.py",
    "scripts/cwo_core/native_pool_scheduler.py",
    "scripts/cwo_core/native_live_availability.py",
    "scripts/cwo_core/supervision/transport/app_server.py",
    "scripts/cwo_core/supervision/transport/errors.py",
    "scripts/cwo_core/supervision/transport/private_io.py",
    "scripts/cwo_core/supervision/callback_timing.py",
    "scripts/cwo_core/supervision/containment.py",
    "scripts/cwo_core/supervision/live_thread.py",
    "scripts/cwo_core/supervision/session_evidence.py",
)


def adapter_implementation_sha256() -> str:
    """Digest current callback and shared adapter sources."""

    return domain_sha256(
        {
            relative: sha256_bytes((ROOT / relative).read_bytes())
            for relative in ADAPTER_IMPLEMENTATION_PATHS
        },
        domain="native-adapter-implementation-sources",
    )


def capability_certification() -> dict[str, Any]:
    policy = callback_certification_policy()
    return {
        **policy,
        "policy_sha256": callback_certification_policy_sha256(policy),
        "adapter_implementation_sha256": adapter_implementation_sha256(),
    }


def _measure_action_ms(
    action: Callable[[], Any],
    *,
    guard_seconds: float = 0.0,
) -> tuple[Any, float]:
    started = time.monotonic_ns()
    result = action()
    if guard_seconds != 0.0:
        time.sleep(guard_seconds)
    elapsed_ms = (time.monotonic_ns() - started) / 1_000_000
    return result, elapsed_ms


def guarded_measure(
    samples: dict[str, list[float]],
    name: str,
    action: Callable[[], Any],
    *,
    guard_seconds: float = 0.20,
) -> Any:
    result, elapsed_ms = _measure_action_ms(
        action,
        guard_seconds=guard_seconds,
    )
    samples.setdefault(name, []).append(elapsed_ms)
    return result


def pool_sleep(*, seconds: float) -> None:
    """Adapt the coordinator's keyword callback to positional-only time.sleep."""

    time.sleep(seconds)
