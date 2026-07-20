"""Read-only compatibility for frozen capacity-two artifacts.

No operative policy or newly emitted pool artifact may use these names.  They
remain here only so historical capability and live-campaign evidence can be
inspected during the documented deprecation window.
"""

from __future__ import annotations

from typing import Any, Mapping


LEGACY_CONCURRENT_CAPACITY = 2
LEGACY_CERTIFICATION_VERSION = "live-thread-adapter-callback-certification:v1"
LEGACY_SCHEDULER_MODEL = "nonpreemptive-edf-cap2-v1"
LEGACY_RESPONSE_TIME_EQUATION = "max_lifecycle+2*check+scheduler<=poll_interval"


def is_legacy_capability_certification(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and value.get("version") == LEGACY_CERTIFICATION_VERSION
        and value.get("scheduler_model") == LEGACY_SCHEDULER_MODEL
        and value.get("response_time_equation") == LEGACY_RESPONSE_TIME_EQUATION
    )


def historical_release_snapshot(
    *,
    status: Any,
    released_max_active_workers: Any,
) -> dict[str, Any]:
    """Project generalized policy into a frozen v1 campaign field set."""

    return {
        "status": status,
        "cap_two_operative_release": (
            isinstance(released_max_active_workers, int)
            and not isinstance(released_max_active_workers, bool)
            and released_max_active_workers >= LEGACY_CONCURRENT_CAPACITY
        ),
    }
