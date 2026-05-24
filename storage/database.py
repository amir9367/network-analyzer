import sqlite3
from contextlib import contextmanager

DB_PATH = "packets.db"

def init_db():
    """Create tables if they don't exist."""
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip    TEXT,
                dst_ip    TEXT,
                src_port  INTEGER,
                dst_port  INTEGER,
                protocol  TEXT,
                size      INTEGER
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                alert_type TEXT,
                src_ip    TEXT,
                detail    TEXT
            )
        """)

@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row   # Rows behave like dicts
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def insert_packet(data: dict):
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, size)
            VALUES (:timestamp, :src_ip, :dst_ip, :src_port, :dst_port, :protocol, :size)
        """, data)

def insert_alert(alert_type: str, src_ip: str, detail: str):
    from datetime import datetime
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO alerts (timestamp, alert_type, src_ip, detail)
            VALUES (?, ?, ?, ?)
        """, (datetime.utcnow().isoformat(), alert_type, src_ip, detail))

def query_recent_packets(limit=200):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM packets ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]   # ← aligned with 'with', NOT inside it

def query_recent_alerts(limit=50):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]   # ← same here