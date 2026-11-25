#!/usr/bin/env python3
"""Validate the archived three-arm study. The full offline tools are in v1.33.0."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
from collections.abc import Iterator
from pathlib import Path


# The 75 files in evaluation/three-arm at the v1.33.0 commit.
ARCHIVE_FILE_COUNT = 75
ARCHIVE_SHA256 = "397b78a5fca96352af3a3be9c3f99dba8152f8cd79ac6b7fb3764f13664ba824"
BUILD_SLOTS = ("codex_harness", "observer_harness")


def _archive_files(root: Path) -> Iterator[str]:
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in directory.iterdir():
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                pending.append(path)
            elif not stat.S_ISREG(mode):
                raise ValueError(f"archive contains a nonregular file: {path.relative_to(root)}")
            elif path.parent.name != "__pycache__" or path.suffix != ".pyc":
                yield path.relative_to(root).as_posix()


def validate_archive(root: Path) -> dict[str, object]:
    files = sorted(_archive_files(root))
    if len(files) != ARCHIVE_FILE_COUNT:
        raise ValueError(f"archive has {len(files)} files, expected {ARCHIVE_FILE_COUNT}")

    digest = hashlib.sha256()
    metadata = {}
    for name in files:
        data = (root / name).read_bytes()
        file_digest = hashlib.sha256(data).hexdigest()
        digest.update(f"{name}\0{file_digest}\n".encode("utf-8"))
        if name in {"build-freeze.json", "protocol.json"}:
            metadata[name] = data
    if digest.hexdigest() != ARCHIVE_SHA256:
        raise ValueError("archive file paths or contents differ from v1.33.0")

    freeze = json.loads(metadata["build-freeze.json"])
    empty_slot = {"form": None, "reference": None, "sha256": None}
    if any(freeze.get(slot) != empty_slot for slot in BUILD_SLOTS):
        raise ValueError("both archived build slots must be unbound")
    protocol = json.loads(metadata["protocol.json"])
    return {
        "valid": True,
        "protocol_id": protocol["protocol_id"],
        "digest": protocol["preregistration"]["digest"],
        "build_freeze_complete": False,
        "unbound_builds": list(BUILD_SLOTS),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, help="archived study directory (default: evaluation/history/three-arm)")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate", help="check the frozen archive files and unbound builds")
    run = commands.add_parser("run", help="refused: running an arm is a held external effect")
    run.add_argument("--arm", help="ignored; every arm is refused")
    run.add_argument("--authorization", help="ignored; no authorization is recognized")
    args, extra = parser.parse_known_args(argv)
    if args.command == "run":
        print(
            "refused: running a study arm is a held external effect (the paid comparative "
            "evaluation); this version recognizes no authorization for it, so nothing was started",
            file=sys.stderr,
        )
        return 3
    if extra:
        parser.error(f"unrecognized arguments: {' '.join(extra)}")

    root = args.root or Path(__file__).resolve().parents[1] / "evaluation/history/three-arm"
    try:
        report = validate_archive(root)
    except OSError as exc:
        print(f"archive is unreadable: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        report = {"valid": False, "errors": [str(exc)]}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
