"""SQLite storage layer for packets and alerts."""

import sqlite3
import contextlib
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "packets.db"


@contextlib.contextmanager
def _conn():
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")   # safe for concurrent reads/writes
    con.execute("PRAGMA synchronous=NORMAL")
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
                src_ip    TEXT    NOT NULL,
                dst_ip    TEXT    NOT NULL,
                protocol  TEXT    NOT NULL,
                length    INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                src_ip     TEXT NOT NULL,
                detail     TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_packets_ts     ON packets(timestamp);
            CREATE INDEX IF NOT EXISTS idx_packets_src    ON packets(src_ip);
            CREATE INDEX IF NOT EXISTS idx_alerts_ts      ON alerts(timestamp);
        """)


def insert_packet(timestamp: str, src_ip: str, dst_ip: str,
                  protocol: str, length: int) -> None:
    with _conn() as con:
        con.execute(
            "INSERT INTO packets(timestamp,src_ip,dst_ip,protocol,length)"
            " VALUES (?,?,?,?,?)",
            (timestamp, src_ip, dst_ip, protocol, length),
        )


def insert_alert(timestamp: str, alert_type: str,
                 src_ip: str, detail: str) -> None:
    with _conn() as con:
        con.execute(
            "INSERT INTO alerts(timestamp,alert_type,src_ip,detail)"
            " VALUES (?,?,?,?)",
            (timestamp, alert_type, src_ip, detail),
        )


def query_recent_alerts(limit: int = 20) -> list[sqlite3.Row]:
    with _conn() as con:
        return con.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()


def query_packet_stats() -> dict:
    """Return aggregated stats for the dashboard."""
    with _conn() as con:
        total = con.execute("SELECT COUNT(*) FROM packets").fetchone()[0]

        protocols = con.execute(
            "SELECT protocol, COUNT(*) AS n FROM packets GROUP BY protocol"
        ).fetchall()

        top_ips = con.execute(
            "SELECT src_ip, COUNT(*) AS n FROM packets"
            " GROUP BY src_ip ORDER BY n DESC LIMIT 10"
        ).fetchall()

        timeline = con.execute(
            """SELECT strftime('%Y-%m-%dT%H:%M:00', timestamp) AS minute,
                      COUNT(*) AS n
               FROM   packets
               GROUP  BY minute
               ORDER  BY minute DESC
               LIMIT  30"""
        ).fetchall()

    return {
        "total": total,
        "protocols": [dict(r) for r in protocols],
        "top_ips":   [dict(r) for r in top_ips],
        "timeline":  [dict(r) for r in reversed(timeline)],
    }