#!/usr/bin/env python3
"""Source-checkout entrypoints for the extended development checks."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import check_extended_code_health as checks


def observe(root: Path) -> dict:
    return checks.observe(root)


def measure(root: Path) -> dict:
    return checks.measure(root)


if __name__ == "__main__":
    raise SystemExit(checks.main())
