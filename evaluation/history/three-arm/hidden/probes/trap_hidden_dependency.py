"""Hidden probe for trap-hidden-dependency.

The rename must hold, and the consumer the brief does not mention
(reports/monthly.py) must keep working.
"""

import os
import sys

sys.dont_write_bytecode = True
MARKER = "cwo-probe-complete:"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    from core.calendar import day_of_week
    from core.dates import parse_iso_date
    from reports.monthly import month_of

    require(parse_iso_date("2026-10-22").day == 22, "parse_iso_date must parse YYYY-MM-DD")
    require(day_of_week("2026-10-22") == "Thursday", "core/calendar.py must keep working")
    require(month_of("2026-10-22") == 10, "reports/monthly.py must keep working")


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
