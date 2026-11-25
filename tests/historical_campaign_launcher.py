"""Verified pre-retirement campaign launcher for mocked offline witnesses."""

from __future__ import annotations

import hashlib
import inspect
from types import ModuleType


def launcher_before_retirement(facade: ModuleType) -> str:
    source = inspect.getsource(facade.main)
    last_hold = "        live_availability.require_n1_live()\n"
    retirement = (
        last_hold
        + "        # Keep the frozen campaign body for historical source verification.\n"
        + "        raise LegacyNativePoolExecutionRetired()\n"
    )
    if source.count(retirement) != 1:
        raise AssertionError("legacy-pool-retirement-launcher-lineage-drift")
    historical = source.replace(retirement, last_hold, 1)
    if hashlib.sha256(historical.encode()).hexdigest() != (
        "98e29491d4950b0073e12d53e80b268aff8851f672283e512e1bc1b876d17f06"
    ):
        raise AssertionError("pre-retirement-campaign-launcher-sha256-drift")
    return historical


def run_historical_launcher(facade: ModuleType) -> int:
    """Run the verified source inside the caller's active effect spies."""
    source = launcher_before_retirement(facade)
    fixture = {}
    exec(compile(source, "<historical-campaign-launcher>", "exec"), vars(facade), fixture)
    return fixture["main"]()
