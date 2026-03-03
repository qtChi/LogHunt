# ==============================================================================
# loghunter/audit/logger.py
#
# AuditLogger — append-only SQLite audit writer.
#
# Per spec section 24:
#   - Cannot be cleared via any application interface.
#   - log_query never raises on write failure — logs to stderr instead.
#   - log_ingest and log_rule_event raise TypeError if entry is None.
#   - get_query_history raises ValueError if limit < 1.
#   - Backed by SQLiteLayer — no direct SQLite access.
#
# Build Priority: Phase 1
# ==============================================================================

from __future__ import annotations

import sys
from typing import Optional

from loghunter.engine.sqlite_layer import SQLiteLayer
from loghunter.schema.audit_models import (
    IngestAuditEntry,
    QueryAuditEntry,
    RuleAuditEntry,
)


class AuditLogger:
    """
    Append-only audit log writer backed by SQLiteLayer.

    Per spec section 24. All writes go through SQLiteLayer — no direct
    SQLite access. The audit log cannot be cleared via any public method.
    """

    def __init__(self, sqlite_layer: SQLiteLayer) -> None:
        """
        Initialise AuditLogger with an open SQLiteLayer.

        Tables are created by SQLiteLayer._ensure_tables() — no DDL here.

        Args:
            sqlite_layer: Initialised SQLiteLayer instance.

        Raises:
            TypeError: If sqlite_layer is None.
        """
        if sqlite_layer is None:
            raise TypeError("sqlite_layer must not be None")
        self._db = sqlite_layer

    # --------------------------------------------------------------------------
    # Write methods
    # --------------------------------------------------------------------------

    def log_query(self, entry: QueryAuditEntry) -> None:
        """
        Append a query audit entry.

        Never raises on write failure — logs error to stderr instead.
        This ensures a failed audit write never disrupts an analyst query.

        Args:
            entry: QueryAuditEntry to persist.

        Raises:
            TypeError: If entry is None.
        """
        if entry is None:
            raise TypeError("entry must not be None")
        try:
            self._db.execute_write(
                """INSERT INTO query_audit
                   (session_id, sql_template, event_class, success,
                    row_count, latency_ms, failure_reason, executed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    entry.session_id,
                    entry.sql_template,
                    entry.event_class,
                    1 if entry.success else 0,
                    entry.row_count,
                    entry.latency_ms,
                    entry.failure_reason,
                    entry.executed_at,
                ),
            )
        except Exception as exc:
            print(
                f"AuditLogger.log_query write failure: {exc}",
                file=sys.stderr,
            )

    def log_ingest(self, entry: IngestAuditEntry) -> None:
        """
        Append an ingest audit entry.

        Args:
            entry: IngestAuditEntry to persist.

        Raises:
            TypeError: If entry is None.
        """
        if entry is None:
            raise TypeError("entry must not be None")
        self._db.execute_write(
            """INSERT INTO ingest_audit
               (ingest_id, source_format, event_count,
                failed_count, file_path, ingested_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                entry.ingest_id,
                entry.source_format,
                entry.event_count,
                entry.failed_count,
                entry.file_path,
                entry.ingested_at,
            ),
        )

    def log_rule_event(self, entry: RuleAuditEntry) -> None:
        """
        Append a rule lifecycle event entry.

        Args:
            entry: RuleAuditEntry to persist.

        Raises:
            TypeError: If entry is None.
        """
        if entry is None:
            raise TypeError("entry must not be None")
        self._db.execute_write(
            """INSERT INTO rule_audit
               (rule_id, event_type, session_id, detail, occurred_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                entry.rule_id,
                entry.event_type,
                entry.session_id,
                entry.detail,
                entry.occurred_at,
            ),
        )

    # --------------------------------------------------------------------------
    # Read methods
    # --------------------------------------------------------------------------

    def get_query_history(
        self,
        session_id: Optional[str] = None,
        limit: int = 100,
    ) -> list[QueryAuditEntry]:
        """
        Return query audit entries, optionally filtered by session.

        Args:
            session_id: If provided, only entries for this session returned.
            limit:      Maximum number of entries to return.

        Returns:
            List of QueryAuditEntry objects, most recent first.
            Empty list if no entries match.

        Raises:
            ValueError: If limit is less than 1.
        """
        if limit < 1:
            raise ValueError(f"limit must be at least 1, got {limit}")

        if session_id is not None:
            rows = self._db.execute_read(
                """SELECT * FROM query_audit
                   WHERE session_id = ?
                   ORDER BY id DESC
                   LIMIT ?""",
                (session_id, limit),
            )
        else:
            rows = self._db.execute_read(
                """SELECT * FROM query_audit
                   ORDER BY id DESC
                   LIMIT ?""",
                (limit,),
            )

        return [self._row_to_query_entry(r) for r in rows]

    def get_ingest_history(self, limit: int = 50) -> list[IngestAuditEntry]:
        """
        Return most recent ingest audit entries.

        Args:
            limit: Maximum number of entries to return.

        Returns:
            List of IngestAuditEntry objects, most recent first.
            Empty list if no entries.

        Raises:
            ValueError: If limit is less than 1.
        """
        if limit < 1:
            raise ValueError(f"limit must be at least 1, got {limit}")

        rows = self._db.execute_read(
            """SELECT * FROM ingest_audit
               ORDER BY id DESC
               LIMIT ?""",
            (limit,),
        )
        return [self._row_to_ingest_entry(r) for r in rows]

    # --------------------------------------------------------------------------
    # Internal row mappers
    # --------------------------------------------------------------------------

    def _row_to_query_entry(self, row: dict) -> QueryAuditEntry:
        return QueryAuditEntry(
            session_id=row["session_id"],
            sql_template=row["sql_template"],
            event_class=row["event_class"],
            success=bool(row["success"]),
            row_count=row["row_count"],
            latency_ms=row["latency_ms"],
            failure_reason=row["failure_reason"],
            executed_at=row["executed_at"],
        )

    def _row_to_ingest_entry(self, row: dict) -> IngestAuditEntry:
        return IngestAuditEntry(
            ingest_id=row["ingest_id"],
            source_format=row["source_format"],
            event_count=row["event_count"],
            failed_count=row["failed_count"],
            file_path=row["file_path"],
            ingested_at=row["ingested_at"],
        )