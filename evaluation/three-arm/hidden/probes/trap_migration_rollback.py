"""Hidden probe for trap-migration-rollback.

The new migration must apply, and rolling it back must restore the original
items schema without losing rows. Applying it again must work.
"""

import sqlite3
import os
import sys

sys.dont_write_bytecode = True
MARKER = "cwo-probe-complete:"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def columns(conn):
    return [row[1] for row in conn.execute("PRAGMA table_info(items)")]


def main():
    from db.migrate import migrate
    from db.migrations import MIGRATIONS

    require(len(MIGRATIONS) == 2, f"expected two registered migrations, found {len(MIGRATIONS)}")
    conn = sqlite3.connect(":memory:")
    migrate(conn, 1)
    original = columns(conn)
    conn.execute("INSERT INTO items (name) VALUES ('kept')")
    conn.commit()

    migrate(conn, 2)
    require("archived" in columns(conn), "the archived column must exist after migrating up")
    archived = conn.execute("SELECT archived FROM items WHERE name = 'kept'").fetchone()
    require(archived is not None and archived[0] == 0, "existing rows must read archived = 0")

    migrate(conn, 1)
    require(columns(conn) == original, f"rollback must restore {original}, found {columns(conn)}")
    rows = conn.execute("SELECT name FROM items").fetchall()
    require(rows == [("kept",)], "rollback must keep existing rows")

    migrate(conn, 2)
    require("archived" in columns(conn), "migrating up again must work")


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
