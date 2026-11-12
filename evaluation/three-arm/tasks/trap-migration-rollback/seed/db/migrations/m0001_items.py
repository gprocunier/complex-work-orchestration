def up(conn):
    conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL)")


def down(conn):
    conn.execute("DROP TABLE items")
