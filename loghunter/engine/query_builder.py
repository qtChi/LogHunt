"""
QueryBuilder — Phase 2
Builds and executes DuckDB queries over OCSF Parquet partitions.
Hardcoded include_replay=False per D-009.
Zero string interpolation: field names validated against registry;
numeric values embedded by type; string values single-quote escaped.
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from loghunter.audit.logger import AuditLogger
from loghunter.engine.duckdb_layer import DuckDBLayer
from loghunter.exceptions import PartitionNotFoundError
from loghunter.schema.audit_models import QueryAuditEntry
from loghunter.schema.ocsf_event import OCSFEvent
from loghunter.schema.ocsf_field_registry import OCSFFieldRegistry


def _escape_string(value: str) -> str:
    """Escape single quotes for DuckDB string literals."""
    return str(value).replace("'", "''")


class QueryBuilder:
    """
    Builds parameterised SQL queries for DuckDB and converts results
    back to OCSFEvent objects.
    """

    def __init__(
        self,
        duckdb_layer: DuckDBLayer,
        registry: OCSFFieldRegistry,
        audit_logger: AuditLogger,
    ) -> None:
        """
        Raises TypeError if any argument is None.
        """
        if duckdb_layer is None:
            raise TypeError("duckdb_layer must not be None")
        if registry is None:
            raise TypeError("registry must not be None")
        if audit_logger is None:
            raise TypeError("audit_logger must not be None")

        self._duckdb = duckdb_layer
        self._registry = registry
        self._audit = audit_logger

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_sql(
        self,
        class_uid: int,
        filters: Optional[dict[str, Any]] = None,
        time_range: Optional[tuple[datetime, datetime]] = None,
    ) -> str:
        """
        Returns a SELECT * SQL string with a ``{partition}`` placeholder
        suitable for DuckDBLayer.execute_query.

        Field names in *filters* are validated against the registry for
        *class_uid* — invalid field names are silently dropped (prevents
        injection; only registered OCSF paths reach the WHERE clause).

        Raises:
            TypeError:               If class_uid is None.
            PartitionNotFoundError:  If no Parquet partition exists for
                                     class_uid (checked via
                                     DuckDBLayer.get_available_partitions).
        """
        if class_uid is None:
            raise TypeError("class_uid must not be None")

        available = self._duckdb.get_available_partitions()
        if class_uid not in available:
            raise PartitionNotFoundError(
                f"No Parquet partition found for class_uid={class_uid}"
            )

        conditions: list[str] = []

        if time_range is not None:
            start, end = time_range
            start_iso = start.strftime("%Y-%m-%dT%H:%M:%S")
            end_iso = end.strftime("%Y-%m-%dT%H:%M:%S")
            conditions.append(f"time >= '{start_iso}'")
            conditions.append(f"time <= '{end_iso}'")

        if filters:
            for field_path, value in filters.items():
                if not self._registry.is_valid_field(field_path, class_uid):
                    continue  # silently drop unregistered / wrong-class fields
                conditions.append(self._build_condition(field_path, value))

        where_clause = ""
        if conditions:
            where_clause = " WHERE " + " AND ".join(conditions)

        return f"SELECT * FROM {{partition}}{where_clause}"

    def execute(
        self,
        class_uid: int,
        filters: Optional[dict[str, Any]] = None,
        time_range: Optional[tuple[datetime, datetime]] = None,
    ) -> list[OCSFEvent]:
        """
        Builds SQL, executes against DuckDB (include_replay=False per D-009),
        converts rows → OCSFEvent, and writes a QueryAuditEntry.

        Raises:
            TypeError:               If class_uid is None.
            PartitionNotFoundError:  If no partition for class_uid.
        """
        session_id = str(uuid.uuid4())
        start_ts = time.monotonic()
        success = True
        row_count = 0
        failure_reason: Optional[str] = None
        events: list[OCSFEvent] = []
        sql = "(build failed)"

        try:
            sql = self.build_sql(class_uid, filters, time_range)
            rows = self._duckdb.execute_query(
                sql,
                class_uid,
                include_replay=False,
                session_id=None,
            )
            row_count = len(rows)
            for row in rows:
                event = self._row_to_event(row, class_uid)
                if event is not None:
                    events.append(event)
        except Exception as exc:
            success = False
            failure_reason = str(exc)
            raise
        finally:
            latency_ms = (time.monotonic() - start_ts) * 1000
            entry = QueryAuditEntry(
                session_id=session_id,
                sql_template=sql,
                event_class=class_uid,
                success=success,
                row_count=row_count if success else None,
                latency_ms=latency_ms,
                failure_reason=failure_reason,
            )
            self._audit.log_query(entry)

        return events

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_condition(self, field_path: str, value: Any) -> str:
        """
        Build a single WHERE condition for *field_path* = *value*.
        Numeric types are embedded directly; everything else is
        single-quote escaped.
        """
        if value is None:
            return f"{field_path} IS NULL"
        if isinstance(value, bool):
            # bool before int — bool is a subclass of int
            return f"{field_path} = {1 if value else 0}"
        if isinstance(value, (int, float)):
            return f"{field_path} = {value}"
        return f"{field_path} = '{_escape_string(value)}'"

    def _row_to_event(self, row: dict, class_uid: int) -> Optional[OCSFEvent]:
        """
        Convert a DuckDB result row (flat dict with dot-notation keys)
        back to an OCSFEvent.  Returns None if the row cannot be
        reconstructed (missing required fields, invalid values).
        """
        try:
            data = dict(row)

            raw_time = data.pop("time", None)
            time_val = self._parse_time(raw_time)

            activity_id = self._safe_int(data.pop("activity_id", None))
            severity_id = self._safe_int(data.pop("severity_id", None))
            metadata_log_source = str(data.pop("metadata.log_source", "") or "unknown")
            metadata_original_time = str(
                data.pop("metadata.original_time", "") or "unknown"
            )
            # class_uid may be in the row as well — drop it
            data.pop("class_uid", None)

            # Only pass kwargs that are valid for this class
            kwargs = {
                k: v
                for k, v in data.items()
                if v is not None and self._registry.is_valid_field(k, class_uid)
            }

            return OCSFEvent(
                class_uid=class_uid,
                activity_id=activity_id,
                severity_id=severity_id,
                time=time_val,
                metadata_log_source=metadata_log_source,
                metadata_original_time=metadata_original_time,
                registry=self._registry,
                **kwargs,
            )
        except Exception:
            return None

    @staticmethod
    def _parse_time(raw: Any) -> datetime:
        """Parse a stored time value back to a timezone-aware datetime."""
        if isinstance(raw, datetime):
            if raw.tzinfo is None:
                return raw.replace(tzinfo=timezone.utc)
            return raw
        if raw is None:
            return datetime.now(timezone.utc)
        try:
            dt = datetime.fromisoformat(str(raw))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            return datetime.now(timezone.utc)

    @staticmethod
    def _safe_int(value: Any) -> int:
        """Convert stored value to int; returns 0 on failure."""
        if value is None:
            return 0
        try:
            return int(value)
        except (ValueError, TypeError):
            return 0