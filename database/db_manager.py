"""SQLite persistence layer for ransomware monitoring signals."""

from __future__ import annotations

import logging
import sqlite3
import threading
import argparse
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Thread-safe SQLite manager for events, alerts, and scores."""

    def __init__(self, db_path: str | None = None) -> None:
        project_root = Path(__file__).resolve().parent.parent
        self._db_path = Path(db_path) if db_path else project_root / "ransomware_monitor.db"
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS file_events(
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT,
                    event_type TEXT,
                    file_path TEXT,
                    file_size INTEGER,
                    process_name TEXT
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS drift_alerts(
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT,
                    severity TEXT,
                    top_feature TEXT,
                    top_z_score REAL,
                    write_rate REAL,
                    rename_count INTEGER,
                    detectors_fired INTEGER
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS risk_scores(
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT,
                    score REAL,
                    level TEXT,
                    entropy_flag INTEGER,
                    triggered_response INTEGER
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS entropy_alerts(
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT,
                    file_path TEXT,
                    entropy REAL,
                    threshold REAL
                )
                """
            )
            self._conn.commit()

    def insert_file_event(
        self,
        timestamp: str,
        event_type: str,
        file_path: str,
        file_size: int,
        process_name: str,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO file_events(timestamp, event_type, file_path, file_size, process_name)
                VALUES (?, ?, ?, ?, ?)
                """,
                (timestamp, event_type, file_path, file_size, process_name),
            )
            self._conn.commit()

    def insert_drift_alert(
        self,
        timestamp: str,
        severity: str,
        top_feature: str | None,
        top_z_score: float,
        write_rate: float,
        rename_count: int,
        detectors_fired: int,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO drift_alerts(
                    timestamp, severity, top_feature, top_z_score, write_rate,
                    rename_count, detectors_fired
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    severity,
                    top_feature,
                    top_z_score,
                    write_rate,
                    rename_count,
                    detectors_fired,
                ),
            )
            self._conn.commit()

    def insert_risk_score(
        self,
        timestamp: str,
        score: float,
        level: str,
        entropy_flag: int,
        triggered_response: int,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO risk_scores(timestamp, score, level, entropy_flag, triggered_response)
                VALUES (?, ?, ?, ?, ?)
                """,
                (timestamp, score, level, entropy_flag, triggered_response),
            )
            self._conn.commit()

    def insert_entropy_alert(
        self,
        timestamp: str,
        file_path: str,
        entropy: float,
        threshold: float,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO entropy_alerts(timestamp, file_path, entropy, threshold)
                VALUES (?, ?, ?, ?)
                """,
                (timestamp, file_path, entropy, threshold),
            )
            self._conn.commit()

    def query_recent(self, table: str, limit: int = 50) -> list[dict[str, Any]]:
        valid_tables = {"file_events", "drift_alerts", "risk_scores", "entropy_alerts"}
        if table not in valid_tables:
            raise ValueError(f"Unsupported table: {table}")

        with self._lock:
            cursor = self._conn.execute(
                f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def main() -> None:
    """CLI entry point for quick database inspection."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    parser = argparse.ArgumentParser(description="SQLite manager for monitoring data")
    parser.add_argument(
        "--table",
        choices=["file_events", "drift_alerts", "risk_scores", "entropy_alerts"],
        default="risk_scores",
    )
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()

    manager = DatabaseManager()
    try:
        rows = manager.query_recent(args.table, limit=args.limit)
        for row in rows:
            print(row)
    finally:
        manager.close()


if __name__ == "__main__":
    main()
