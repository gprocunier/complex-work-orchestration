#!/usr/bin/env python3
"""Check the installed Codex CLI against CWO's offline app-server contract."""

import argparse
import sys

from cwo_core.codex_protocol_capabilities import CapabilityError, check_codex_capabilities


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", default="codex", help="Codex executable (default: codex on PATH)")
    args = parser.parse_args()
    try:
        check_codex_capabilities(args.codex)
    except CapabilityError as exc:
        print(f"Codex app-server protocol contract failed. {exc}", file=sys.stderr)
        return 1
    print("Codex app-server protocol contract passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
