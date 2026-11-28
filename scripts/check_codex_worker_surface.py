#!/usr/bin/env python3
"""Refuse the retired connected-Codex worker tool-surface capture route."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import native_live_availability as live_availability  # noqa: E402
from cwo_core.codex_tool_surface import (  # noqa: E402
    EXACT_OPERATIVE_TOOLS,
    EXACT_READ_ONLY_TOOLS,
    EXACT_CORE_RESOURCE_OPERATIVE_TOOLS,
    EXACT_CORE_RESOURCE_READ_ONLY_TOOLS,
    tools_are_mutable,
    normalized_tools,
)


EXACT_TOOLS = list(EXACT_OPERATIVE_TOOLS)


def capture_tool_request(
    *,
    codex_home: Path,
    requested_model: str,
    timeout_seconds: float,
    permitted_tools: list[str] | tuple[str, ...] = tuple(EXACT_TOOLS),
    catalog_projection: Path | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate the exact tool profile and refuse new capture requests."""
    normalized_tools(permitted_tools)
    live_availability.require_n1_live()
    raise live_availability.NativeLiveUnavailable("native-n1-live-unavailable")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--capture", type=Path)
    parser.add_argument("--profile", choices=("mutating", "read-only", "mutating-core-resources-v2",
                                              "read-only-core-resources-v2"), default="mutating")
    parser.add_argument("--catalog-projection", type=Path)
    parser.add_argument("--host-evidence", type=Path)
    parser.add_argument(
        "--codex-home",
        type=Path,
        default=Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")),
    )
    parser.add_argument("--model")
    parser.add_argument("--timeout-seconds", type=float, default=15.0)
    args = parser.parse_args()
    if args.timeout_seconds <= 0 or args.timeout_seconds > 120:
        parser.error("--timeout-seconds must be in (0, 120]")
    tools = list({"mutating": EXACT_TOOLS, "read-only": EXACT_READ_ONLY_TOOLS,
                  "mutating-core-resources-v2": EXACT_CORE_RESOURCE_OPERATIVE_TOOLS,
                  "read-only-core-resources-v2": EXACT_CORE_RESOURCE_READ_ONLY_TOOLS}[args.profile])
    if (not tools_are_mutable(tools)) != (args.catalog_projection is not None):
        parser.error("read-only requires --catalog-projection; mutating forbids it")
    live_availability.require_n1_live()
    raise live_availability.NativeLiveUnavailable("native-n1-live-unavailable")


if __name__ == "__main__":
    raise SystemExit(main())
