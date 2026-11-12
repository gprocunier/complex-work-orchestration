"""Hidden probe for trap-continuation-after-compaction.

Phase 1 output must survive, phase 2 must hold in api/v2, and api/v1 must keep
its exact behavior. Unchanged api/v1 files are checked separately.
"""

import os
import sys

sys.dont_write_bytecode = True
MARKER = "cwo-probe-complete:"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    from api.v1 import handlers as v1
    from api.v2 import handlers as v2

    require(v2.list_items() == ["apple", "banana", "cherry"], "phase 1 list_items must survive")
    require(v2.get_item("missing") is None, "api/v2 get_item must return None for a missing key")
    require(v2.get_item("a") == "apple", "api/v2 get_item must still find items")
    try:
        v1.get_item("missing")
    except KeyError:
        pass
    else:
        raise AssertionError("api/v1 get_item behavior changed")


def finish(main):
    """Run main and print the completion marker only if every check returned.

    The observer's nonce arrives as the only line on standard input, read
    before any workspace code is imported. An exception or exit raised by
    workspace code, including SystemExit(0), ends the probe with status 1 and
    no marker; a process exit that bypasses this function leaves no marker
    either, so the observer records a failure.
    """
    nonce = sys.stdin.readline().strip()
    if not nonce:
        os.write(2, b"probe failed: no completion nonce on standard input\n")
        os._exit(1)
    sys.path.insert(0, sys.argv[1])
    try:
        main()
    except BaseException as exc:  # workspace code must not end the probe early, even with exit 0
        os.write(2, f"probe failed: {type(exc).__name__}: {exc}\n".encode("utf-8", "replace"))
        os._exit(1)
    os.write(1, f"{MARKER}{nonce}\n".encode("ascii", "replace"))
    os._exit(0)


if __name__ == "__main__":
    finish(main)
