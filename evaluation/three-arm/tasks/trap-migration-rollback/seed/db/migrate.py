"""Apply migrations up or down to a target version."""

from db.migrations import MIGRATIONS


def current_version(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
    row = conn.execute("SELECT version FROM schema_version").fetchone()
    return row[0] if row else 0


def _set_version(conn, version):
    conn.execute("DELETE FROM schema_version")
    conn.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))


def migrate(conn, target):
    version = current_version(conn)
    while version < target:
        MIGRATIONS[version].up(conn)
        version += 1
        _set_version(conn, version)
    while version > target:
        MIGRATIONS[version - 1].down(conn)
        version -= 1
        _set_version(conn, version)
    conn.commit()
    return version
