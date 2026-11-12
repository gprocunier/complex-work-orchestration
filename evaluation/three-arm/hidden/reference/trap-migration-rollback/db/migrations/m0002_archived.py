def up(conn):
    conn.execute("ALTER TABLE items ADD COLUMN archived INTEGER NOT NULL DEFAULT 0")


def down(conn):
    conn.execute("ALTER TABLE items DROP COLUMN archived")
