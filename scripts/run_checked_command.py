from __future__ import annotations

import argparse
import json
from pathlib import Path

from cwo_core.checked_command import execute_checked_command


def main() -> None:
    parser = argparse.ArgumentParser(description="Preflight and execute one structured checked command.")
    parser.add_argument("spec")
    parser.add_argument("--output")
    args = parser.parse_args()
    spec = json.loads(Path(args.spec).read_text(encoding="utf-8"))
    result = execute_checked_command(spec)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    if result["quarantine_required"]:
        raise SystemExit(3)
    if result["preflight_status"] != "passed":
        raise SystemExit(2)
    if result["execution_status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
