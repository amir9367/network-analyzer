"""
dns_scanner/storage.py
~~~~~~~~~~~~~~~~~~~~~~
Persist DNS scan results to SQLite (alongside the existing packets.db)
and export to CSV / JSON.
"""

import csv
import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .scanner import ProbeResult

logger = logging.getLogger(__name__)

DEFAULT_DB = "dns_scan_results.db"


class ScanResultStore:
    """
    Thin SQLite store for ProbeResult objects.

    Schema
    ------
    dns_scan_results
        id            INTEGER  PK
        scan_id       TEXT     — UUID / timestamp tag shared across one run
        resolver_ip   TEXT
        hostname      TEXT
        success       INTEGER  (0/1)
        matched       INTEGER  (0/1)
        resolved_ips  TEXT     — comma-separated
        response_ms   REAL
        error         TEXT
        created_at    TEXT

    dns_scans
        scan_id       TEXT  PK
        target        TEXT
        expected_ip   TEXT
        cidr_ranges   TEXT  — JSON array
        started_at    TEXT
        finished_at   TEXT
        total_probed  INTEGER
        total_matched INTEGER
    """

    def __init__(self, db_path: str = DEFAULT_DB):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._connect()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS dns_scans (
                scan_id       TEXT PRIMARY KEY,
                target        TEXT NOT NULL,
                expected_ip   TEXT,
                cidr_ranges   TEXT,
                started_at    TEXT,
                finished_at   TEXT,
                total_probed  INTEGER DEFAULT 0,
                total_matched INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS dns_scan_results (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id       TEXT NOT NULL,
                resolver_ip   TEXT NOT NULL,
                hostname      TEXT NOT NULL,
                success       INTEGER NOT NULL,
                matched       INTEGER NOT NULL,
                resolved_ips  TEXT,
                response_ms   REAL,
                error         TEXT,
                created_at    TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES dns_scans(scan_id)
            );

            CREATE INDEX IF NOT EXISTS idx_scan_results_matched
                ON dns_scan_results (scan_id, matched);
        """)
        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_scan(
        self,
        target: str,
        cidr_ranges: List[str],
        expected_ip: Optional[str] = None,
    ) -> str:
        """Register a new scan run and return its scan_id."""
        scan_id = datetime.utcnow().strftime("scan_%Y%m%d_%H%M%S_%f")
        conn = self._connect()
        conn.execute(
            """INSERT INTO dns_scans
               (scan_id, target, expected_ip, cidr_ranges, started_at)
               VALUES (?,?,?,?,?)""",
            (
                scan_id,
                target,
                expected_ip,
                json.dumps(cidr_ranges),
                datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()
        conn.close()
        return scan_id

    def save_results(self, scan_id: str, results: List[ProbeResult]):
        """Bulk-insert ProbeResult list into dns_scan_results."""
        now = datetime.utcnow().isoformat()
        rows = [
            (
                scan_id,
                r.resolver_ip,
                r.hostname,
                int(r.success),
                int(r.matched),
                ",".join(r.resolved_ips),
                r.response_time_ms,
                r.error,
                now,
            )
            for r in results
        ]
        conn = self._connect()
        conn.executemany(
            """INSERT INTO dns_scan_results
               (scan_id, resolver_ip, hostname, success, matched,
                resolved_ips, response_ms, error, created_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            rows,
        )

        matched = sum(1 for r in results if r.matched)
        conn.execute(
            """UPDATE dns_scans SET
               finished_at   = ?,
               total_probed  = ?,
               total_matched = ?
               WHERE scan_id = ?""",
            (datetime.utcnow().isoformat(), len(results), matched, scan_id),
        )
        conn.commit()
        conn.close()

    def get_matches(self, scan_id: str) -> List[dict]:
        """Return all matched results for *scan_id* as dicts."""
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM dns_scan_results WHERE scan_id=? AND matched=1",
            (scan_id,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def list_scans(self) -> List[dict]:
        """Return summary of all scan runs."""
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM dns_scans ORDER BY started_at DESC"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Exports
    # ------------------------------------------------------------------

    def export_csv(self, scan_id: str, path: Optional[str] = None) -> str:
        """Write all results for *scan_id* to CSV.  Returns file path."""
        out = path or f"{scan_id}_results.csv"
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM dns_scan_results WHERE scan_id=?", (scan_id,)
        ).fetchall()
        conn.close()

        with open(out, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys() if rows else [])
            writer.writeheader()
            writer.writerows([dict(r) for r in rows])

        return out

    def export_json(self, scan_id: str, path: Optional[str] = None) -> str:
        """Write matched results for *scan_id* to JSON.  Returns file path."""
        out = path or f"{scan_id}_matches.json"
        matches = self.get_matches(scan_id)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(matches, f, indent=2)
        return out