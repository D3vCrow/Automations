"""SQLite-backed durable store for security alerts.

The Network Intrusion Detector keeps alerts only in memory
(``NetworkMonitor.alerts``), so the whole threat timeline was lost on every
close. This store persists each alert as it fires, so threat history survives
restarts and can be queried by time range, severity, or category.

Design notes (2026-07-10 network-tools audit):
    * Each tool uses its **own** DB file (NID -> ``nid_incidents.db``). No shared
      file across the admin/unprivileged boundary — see the merge decision in
      ``plans/2026-07-10-network-tools-audit.md``.
    * ``ts_epoch`` is stored alongside the display timestamp so date-range
      queries and sorting never re-parse strings.
    * WAL journal mode + indexes on ``ts_epoch`` and ``(severity, category)``
      are enabled up front (the audit flagged NSM's no-WAL/no-index DB).
    * Every method is failure-tolerant: a broken DB degrades to a no-op /
      empty result, never raising into the caller's monitoring loop.
"""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Any, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    ts_epoch   REAL NOT NULL,
    severity   TEXT NOT NULL,
    category   TEXT NOT NULL,
    title      TEXT NOT NULL,
    details    TEXT,
    count      INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT,
    last_seen  TEXT
)
"""


class AlertStore:
    """Durable per-tool SQLite store for alert dictionaries.

    The stored/returned alert shape matches the toolbox's in-memory alert dict:
    ``{"timestamp", "severity", "category", "title", "details"}`` — plus
    ``"_db_id"`` and ``"_ts_epoch"`` on rows read back from disk.
    """

    def __init__(self, db_path: str) -> None:
        """Open (creating if needed) the alerts DB at *db_path*.

        Args:
            db_path: Filesystem path to the SQLite file. Parent dir must exist.
        """
        self.db_path = str(db_path)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        try:
            con = self._connect()
            con.execute("PRAGMA journal_mode=WAL")
            con.execute(_SCHEMA)
            con.execute("CREATE INDEX IF NOT EXISTS idx_alerts_epoch ON alerts(ts_epoch)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_alerts_sev_cat ON alerts(severity, category)")
            con.commit()
            con.close()
        except (sqlite3.Error, OSError):
            pass

    def insert(self, alert: dict, ts_epoch: Optional[float] = None) -> Optional[int]:
        """Persist a new alert and return its row id (or None on failure).

        Args:
            alert: Alert dict (``timestamp``/``severity``/``category``/``title``/
                ``details``).
            ts_epoch: Epoch seconds for the alert. Falls back to
                ``details["_epoch"]`` then to the current time.

        Returns:
            The new row id, or None if the write failed.
        """
        try:
            details = alert.get("details", {}) or {}
            ts = alert.get("timestamp", "")
            if ts_epoch is None:
                ts_epoch = float(details.get("_epoch", 0.0)) or time.time()
            con = self._connect()
            cur = con.execute(
                "INSERT INTO alerts (ts, ts_epoch, severity, category, title, "
                "details, count, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    ts,
                    float(ts_epoch),
                    alert.get("severity", "INFO"),
                    alert.get("category", "SYSTEM"),
                    alert.get("title", ""),
                    json.dumps(details, ensure_ascii=False),
                    int(details.get("_count", 1)),
                    details.get("_first_seen_ts", ts),
                    details.get("_last_seen_ts", ts),
                ),
            )
            row_id = cur.lastrowid
            con.commit()
            con.close()
            return row_id
        except (sqlite3.Error, OSError, TypeError, ValueError):
            return None

    def update_seen(self, row_id: Optional[int], count: int, last_seen: str) -> None:
        """Update a de-duplicated alert's rolling count and last-seen time.

        Args:
            row_id: Row id returned by :meth:`insert` (no-op if falsy).
            count: New occurrence count.
            last_seen: Display timestamp of the latest occurrence.
        """
        if not row_id:
            return
        try:
            con = self._connect()
            con.execute(
                "UPDATE alerts SET count=?, last_seen=? WHERE id=?",
                (int(count), last_seen, int(row_id)),
            )
            con.commit()
            con.close()
        except (sqlite3.Error, OSError, TypeError, ValueError):
            pass

    def load(
        self,
        limit: int = 500,
        severity: str = "ALL",
        category: str = "ALL",
        since_epoch: Optional[float] = None,
        until_epoch: Optional[float] = None,
    ) -> list[dict]:
        """Load alerts newest-first, with optional filters.

        Args:
            limit: Max rows to return.
            severity: Exact severity to match, or ``"ALL"``.
            category: Exact category to match, or ``"ALL"``.
            since_epoch: Lower bound (inclusive) on ``ts_epoch``.
            until_epoch: Upper bound (inclusive) on ``ts_epoch``.

        Returns:
            A list of alert dicts (empty on any failure).
        """
        try:
            con = self._connect()
            con.row_factory = sqlite3.Row
            query = "SELECT * FROM alerts WHERE 1=1"
            params: list[Any] = []
            if severity != "ALL":
                query += " AND severity=?"
                params.append(severity)
            if category != "ALL":
                query += " AND category=?"
                params.append(category)
            if since_epoch is not None:
                query += " AND ts_epoch>=?"
                params.append(float(since_epoch))
            if until_epoch is not None:
                query += " AND ts_epoch<=?"
                params.append(float(until_epoch))
            query += " ORDER BY ts_epoch DESC, id DESC LIMIT ?"
            params.append(int(limit))
            rows = con.execute(query, params).fetchall()
            con.close()
            return [self._row_to_alert(r) for r in rows]
        except (sqlite3.Error, OSError, TypeError, ValueError):
            return []

    @staticmethod
    def _row_to_alert(row: sqlite3.Row) -> dict:
        try:
            details = json.loads(row["details"]) if row["details"] else {}
        except (json.JSONDecodeError, TypeError):
            details = {}
        # DB columns are authoritative for count / first-seen / last-seen.
        details["_count"] = row["count"]
        if row["first_seen"]:
            details["_first_seen_ts"] = row["first_seen"]
        if row["last_seen"]:
            details["_last_seen_ts"] = row["last_seen"]
        return {
            "timestamp": row["ts"],
            "severity": row["severity"],
            "category": row["category"],
            "title": row["title"],
            "details": details,
            "_db_id": row["id"],
            "_ts_epoch": row["ts_epoch"],
        }

    def count(self) -> int:
        """Return the total number of stored alerts (0 on failure)."""
        try:
            con = self._connect()
            n = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            con.close()
            return int(n)
        except (sqlite3.Error, OSError):
            return 0

    def prune_older_than(self, epoch: float) -> int:
        """Delete alerts older than *epoch*; return the number removed.

        Args:
            epoch: Rows with ``ts_epoch`` strictly below this are deleted.

        Returns:
            Count of deleted rows (0 on failure).
        """
        try:
            con = self._connect()
            cur = con.execute("DELETE FROM alerts WHERE ts_epoch < ?", (float(epoch),))
            con.commit()
            removed = cur.rowcount
            con.close()
            return int(removed)
        except (sqlite3.Error, OSError, TypeError, ValueError):
            return 0
