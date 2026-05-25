"""
SQLite storage layer — packets and alerts.
Thread-safe: every call opens its own connection with check_same_thread=False.
"""
import sqlite3
import os
from contextlib import contextmanager

DB_PATH = os.environ.get("NETANALYZER_DB", "packets.db")


@contextmanager
def _conn():
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def init_db() -> None:
    with _conn() as con:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS packets (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT    NOT NULL,
                src_ip    TEXT,
                dst_ip    TEXT,
                protocol  TEXT,
                length    INTEGER
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                src_ip     TEXT,
                detail     TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_packets_ts     ON packets(timestamp);
            CREATE INDEX IF NOT EXISTS idx_packets_src    ON packets(src_ip);
            CREATE INDEX IF NOT EXISTS idx_alerts_ts      ON alerts(timestamp);
        """)


def insert_packet(timestamp: str, src_ip: str, dst_ip: str,
                  protocol: str, length: int) -> None:
    with _conn() as con:
        con.execute(
            "INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length) "
            "VALUES (?, ?, ?, ?, ?)",
            (timestamp, src_ip, dst_ip, protocol, length),
        )


def insert_alert(timestamp: str, alert_type: str,
                 src_ip: str, detail: str) -> None:
    with _conn() as con:
        con.execute(
            "INSERT INTO alerts (timestamp, alert_type, src_ip, detail) "
            "VALUES (?, ?, ?, ?)",
            (timestamp, alert_type, src_ip, detail),
        )


# ── dashboard queries ──────────────────────────────────────────────────────────

def query_recent_alerts(limit: int = 20) -> list[sqlite3.Row]:
    with _conn() as con:
        return con.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()


def query_protocol_counts() -> list[sqlite3.Row]:
    with _conn() as con:
        return con.execute(
            "SELECT protocol, COUNT(*) AS cnt FROM packets GROUP BY protocol"
        ).fetchall()


def query_traffic_timeline(minutes: int = 10) -> list[sqlite3.Row]:
    """Packets per minute for the last *minutes* minutes."""
    with _conn() as con:
        return con.execute(
            """
            SELECT strftime('%Y-%m-%dT%H:%M', timestamp) AS minute,
                   COUNT(*) AS cnt
            FROM   packets
            WHERE  timestamp >= datetime('now', ? || ' minutes')
            GROUP  BY minute
            ORDER  BY minute
            """,
            (f"-{minutes}",),
        ).fetchall()


def query_top_ips(limit: int = 10) -> list[sqlite3.Row]:
    with _conn() as con:
        return con.execute(
            "SELECT src_ip, COUNT(*) AS cnt FROM packets "
            "WHERE src_ip IS NOT NULL "
            "GROUP BY src_ip ORDER BY cnt DESC LIMIT ?",
            (limit,),
        ).fetchall()


def query_recent_packets(limit: int = 50) -> list[sqlite3.Row]:
    with _conn() as con:
        return con.execute(
            "SELECT * FROM packets ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()