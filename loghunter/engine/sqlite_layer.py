# ==============================================================================
# loghunter/engine/sqlite_layer.py
#
# SQLiteLayer — sole write-capable persistent storage layer for application
# metadata alongside ParquetWriter.
#
# Per spec section 11:
#   - Wraps the SQLite connection for all persistent application metadata.
#   - WAL mode enabled on construction.
#   - Only INSERT, UPDATE, DELETE, CREATE permitted on execute_write.
#   - Only SELECT permitted on execute_read.
#   - Zero string interpolation — all values passed as parameters.
#   - close() is idempotent — multiple calls are safe no-ops.
#   - Post-close calls to either execute method raise RuntimeError.
#
# Build Priority: Phase 1
# ==============================================================================

from __future__ import annotations

import sqlite3
from typing import Any


# DML keywords permitted in write statements
_WRITE_KEYWORDS = frozenset({"INSERT", "UPDATE", "DELETE", "CREATE"})

# DML keyword forbidden in write statements
_READ_KEYWORD = "SELECT"


class SQLiteLayer:
    """
    Thin wrapper around a SQLite connection for all persistent application
    metadata: audit log, baselines, rule store.

    Per spec section 11.
    """

    def __init__(self, db_path: str) -> None:
        """
        Open or create a SQLite database at db_path with WAL mode.

        Creates all required tables on first run via _ensure_tables().

        Args:
            db_path: Filesystem path to the SQLite database file.

        Raises:
            TypeError:  If db_path is None.
            ValueError: If db_path is empty or whitespace.
        """
        if db_path is None:
            raise TypeError("db_path must not be None")
        if not str(db_path).strip():
            raise ValueError("db_path must not be empty or whitespace")

        self._db_path = db_path
        self._closed = False
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row

        # Enable WAL mode for concurrent read performance
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.commit()

        self._ensure_tables()

    # --------------------------------------------------------------------------
    # Internal helpers
    # --------------------------------------------------------------------------

    def _ensure_tables(self) -> None:
        """
        Create all required application tables if they do not exist.

        Tables owned by higher-level components (AuditLogger, BaselineEngine,
        SigmaEngine) are created here so the schema is always consistent
        from first connection.
        """
        statements = [
            # Query audit log
            """
            CREATE TABLE IF NOT EXISTS query_audit (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id      TEXT NOT NULL,
                sql_template    TEXT NOT NULL,
                event_class     INTEGER,
                success         INTEGER NOT NULL,
                row_count       INTEGER,
                latency_ms      REAL,
                failure_reason  TEXT,
                executed_at     TEXT NOT NULL
            )
            """,
            # Ingest audit log
            """
            CREATE TABLE IF NOT EXISTS ingest_audit (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ingest_id       TEXT NOT NULL,
                source_format   TEXT NOT NULL,
                event_count     INTEGER NOT NULL,
                failed_count    INTEGER NOT NULL,
                file_path       TEXT,
                ingested_at     TEXT NOT NULL
            )
            """,
            # Rule audit log and rule store
            """
            CREATE TABLE IF NOT EXISTS rule_audit (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id         TEXT NOT NULL,
                event_type      TEXT NOT NULL,
                session_id      TEXT,
                detail          TEXT,
                occurred_at     TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS rules (
                rule_id             TEXT PRIMARY KEY,
                yaml_content        TEXT NOT NULL,
                sha256              TEXT NOT NULL,
                version             INTEGER NOT NULL,
                analyst_confirmed   INTEGER NOT NULL DEFAULT 0,
                confirmed_at        TEXT,
                superseded_by       TEXT,
                created_at          TEXT NOT NULL,
                exported_at         TEXT,
                export_format       TEXT
            )
            """,
            # Computed baselines
            """
            CREATE TABLE IF NOT EXISTS baselines (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_type     TEXT NOT NULL,
                entity_value    TEXT NOT NULL,
                metric_name     TEXT NOT NULL,
                class_uid       INTEGER NOT NULL,
                mean            REAL NOT NULL,
                stddev          REAL NOT NULL,
                observation_count INTEGER NOT NULL,
                window_start    TEXT NOT NULL,
                window_end      TEXT NOT NULL,
                computed_at     TEXT NOT NULL,
                UNIQUE(entity_type, entity_value, metric_name, class_uid)
            )
            """,
            # Metric snapshots
            """
            CREATE TABLE IF NOT EXISTS metric_snapshots (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_at     TEXT NOT NULL,
                payload         TEXT NOT NULL
            )
            """,
        ]
        for stmt in statements:
            self._conn.execute(stmt)
        self._conn.commit()

    def _check_open(self) -> None:
        """Raise RuntimeError if the connection has been closed."""
        if self._closed:
            raise RuntimeError(
                "SQLiteLayer connection is closed. "
                "Cannot execute queries after close()."
            )

    # --------------------------------------------------------------------------
    # Public API — per spec section 11
    # --------------------------------------------------------------------------

    def execute_write(self, sql: str, params: tuple | dict) -> None:
        """
        Execute a write statement (INSERT, UPDATE, DELETE, CREATE).

        SELECT statements are rejected with ValueError.
        All values must be passed as params — zero string interpolation.

        Args:
            sql:    SQL statement string.
            params: Parameter tuple or dict for the statement.

        Raises:
            TypeError:    If sql or params is None.
            ValueError:   If sql starts with SELECT.
            RuntimeError: If called after close().
        """
        if sql is None:
            raise TypeError("sql must not be None")
        if params is None:
            raise TypeError("params must not be None")
        self._check_open()

        sql_upper = sql.strip().upper()
        if sql_upper.startswith(_READ_KEYWORD):
            raise ValueError(
                "execute_write does not permit SELECT statements. "
                "Use execute_read for queries."
            )

        self._conn.execute(sql, params)
        self._conn.commit()

    def execute_read(self, sql: str, params: tuple | dict) -> list[dict]:
        """
        Execute a SELECT query and return results as a list of row dicts.

        Only SELECT statements are permitted.

        Args:
            sql:    SELECT statement string.
            params: Parameter tuple or dict.

        Returns:
            List of row dictionaries. Empty list for zero results.

        Raises:
            TypeError:    If sql or params is None.
            ValueError:   If sql does not start with SELECT.
            RuntimeError: If called after close().
        """
        if sql is None:
            raise TypeError("sql must not be None")
        if params is None:
            raise TypeError("params must not be None")
        self._check_open()

        sql_upper = sql.strip().upper()
        if not sql_upper.startswith(_READ_KEYWORD):
            raise ValueError(
                "execute_read only permits SELECT statements. "
                "Use execute_write for modifications."
            )

        cursor = self._conn.execute(sql, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        """
        Close the SQLite connection.

        Subsequent calls to execute_write or execute_read raise RuntimeError.
        Multiple calls to close() are safe no-ops.
        """
        if self._closed:
            return
        self._closed = True
        self._conn.close()