from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from cwo_core.checked_command_sequence import execute_checked_command_sequence


EXIT_BY_STATUS = {
    "passed": 0,
    "failed": 1,
    "blocked": 2,
    "quarantined": 3,
}


def _load_spec(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


def _atomic_write_text(target: Path, rendered: str) -> bool:
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target.parent,
            prefix=f".{target.name}.",
            delete=False,
        ) as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
            temporary_name = handle.name
        os.replace(temporary_name, target)
    except OSError:
        return False
    finally:
        if temporary_name and os.path.exists(temporary_name):
            os.unlink(temporary_name)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Execute one ordered checked-command sequence.")
    parser.add_argument("spec")
    parser.add_argument("--state", required=True)
    parser.add_argument("--output")
    args = parser.parse_args()

    result = execute_checked_command_sequence(
        _load_spec(Path(args.spec)),
        state_path=args.state,
    )
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        if not _atomic_write_text(Path(args.output), rendered):
            raise SystemExit(2)
    else:
        print(rendered, end="")

    raise SystemExit(EXIT_BY_STATUS.get(result.get("status"), 2))


if __name__ == "__main__":
    main()
