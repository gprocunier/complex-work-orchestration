#!/usr/bin/env python3
"""Copy the disposable first-project starter without touching an existing path."""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]


def create(destination: Path) -> Path:
    destination = destination.expanduser().absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError("destination already exists; choose a new empty project name")
    source = ROOT / "examples" / "first-project" / "starter"
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        destination = create(args.destination)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"create_first_project: {exc}\n")
    print(f"Created starter at {destination}")
    print("Expected first check: python3 -m unittest -v (intentional failures)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
