# ==============================================================================
# loghunter/audit/metrics.py
#
# AuditMetrics — system health and activity metrics from AuditLogger history.
#
# Per spec section 10.2 (Phase 3):
#   - Read-only — never writes to audit log.
#   - get_system_metrics() reads up to 10,000 most recent entries.
#   - rules_stored / rules_confirmed passed in from SigmaEngine since
#     AuditMetrics has no direct access to the rules table.
#   - get_system_metrics() returns zeroed SystemMetrics on any error.
#   - get_query_success_rate() and get_top_event_classes() also never raise.
#
# Build Priority: Phase 3 — #5 in dependency order.
# ==============================================================================

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from loghunter.audit.logger import AuditLogger

# Maps source_format string (stored in ingest_audit) → OCSF class_uid.
# evtx can produce multiple classes — the most common mapping is used here.
# Unmapped formats are skipped in get_top_event_classes.
FORMAT_CLASS_MAP: dict[str, int] = {
    "zeek":   3001,
    "apache": 3002,
    "syslog": 1001,
    "evtx":   6003,   # Auth/Security events are the primary evtx class
}

_MAX_HISTORY = 10_000


@dataclass
class SystemMetrics:
    """
    Snapshot of system health and recent activity.

    Attributes:
        total_queries:        Total queries in audit log.
        successful_queries:   Queries with success=True.
        failed_queries:       Queries with success=False.
        total_ingest_events:  Sum of event_count across all ingest_audit rows.
        total_ingest_runs:    Number of ingest operations logged.
        rules_stored:         Passed in — not read from audit log.
        rules_confirmed:      Passed in — not read from audit log.
        avg_query_latency_ms: Mean latency_ms across successful queries.
                              None if no data.
        last_ingest_at:       Most recent ingested_at timestamp string.
                              None if never.
        last_query_at:        Most recent executed_at timestamp string.
                              None if never.
    """
    total_queries: int = 0
    successful_queries: int = 0
    failed_queries: int = 0
    total_ingest_events: int = 0
    total_ingest_runs: int = 0
    rules_stored: int = 0
    rules_confirmed: int = 0
    avg_query_latency_ms: Optional[float] = None
    last_ingest_at: Optional[str] = None
    last_query_at: Optional[str] = None


class AuditMetrics:
    """
    Computes system health metrics from AuditLogger history.
    Read-only — never writes to audit log.
    """

    def __init__(self, audit_logger: AuditLogger) -> None:
        """
        Raises TypeError if audit_logger is None.
        """
        if audit_logger is None:
            raise TypeError("audit_logger must not be None")
        self._logger = audit_logger

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_system_metrics(
        self,
        rules_stored: int = 0,
        rules_confirmed: int = 0,
    ) -> SystemMetrics:
        """
        Compute and return a SystemMetrics snapshot.

        Reads up to 10,000 most recent query and ingest entries.
        rules_stored and rules_confirmed are passed in from SigmaEngine
        since AuditMetrics has no direct access to the rules table.

        Returns:
            SystemMetrics dataclass.
            Never raises — returns zeroed SystemMetrics on any error.
        """
        try:
            queries = self._logger.get_query_history(limit=_MAX_HISTORY)
            ingests = self._logger.get_ingest_history(limit=_MAX_HISTORY)

            total_queries = len(queries)
            successful = [q for q in queries if q.success]
            successful_queries = len(successful)
            failed_queries = total_queries - successful_queries

            total_ingest_events = sum(
                (i.event_count or 0) for i in ingests
            )
            total_ingest_runs = len(ingests)

            # Average latency across successful queries only
            latencies = [
                q.latency_ms
                for q in successful
                if q.latency_ms is not None
            ]
            avg_latency = (
                sum(latencies) / len(latencies) if latencies else None
            )

            # Most recent timestamps — history is returned newest-first
            last_ingest_at = ingests[0].ingested_at if ingests else None
            last_query_at = queries[0].executed_at if queries else None

            return SystemMetrics(
                total_queries=total_queries,
                successful_queries=successful_queries,
                failed_queries=failed_queries,
                total_ingest_events=total_ingest_events,
                total_ingest_runs=total_ingest_runs,
                rules_stored=rules_stored,
                rules_confirmed=rules_confirmed,
                avg_query_latency_ms=avg_latency,
                last_ingest_at=last_ingest_at,
                last_query_at=last_query_at,
            )
        except Exception:
            return SystemMetrics(
                rules_stored=rules_stored,
                rules_confirmed=rules_confirmed,
            )

    def get_query_success_rate(self) -> float:
        """
        Return percentage of successful queries 0.0–100.0.
        Returns 0.0 if no queries logged.
        Never raises.
        """
        try:
            queries = self._logger.get_query_history(limit=_MAX_HISTORY)
            if not queries:
                return 0.0
            successful = sum(1 for q in queries if q.success)
            return successful / len(queries) * 100.0
        except Exception:
            return 0.0

    def get_top_event_classes(self, limit: int = 5) -> list[tuple[int, int]]:
        """
        Return top event classes by ingest volume.

        Reads ingest_audit entries and groups by source_format.
        Maps source_format → class_uid via FORMAT_CLASS_MAP.
        Entries with unmapped source_format are skipped.

        Args:
            limit: Maximum number of entries to return. Defaults to 5.

        Returns:
            List of (class_uid, event_count) tuples sorted descending
            by count. Empty list if no ingest history.

        Raises:
            ValueError: If limit < 1.
        """
        if limit < 1:
            raise ValueError(f"limit must be at least 1, got {limit}")

        try:
            ingests = self._logger.get_ingest_history(limit=_MAX_HISTORY)
            if not ingests:
                return []

            # Accumulate event_count per class_uid
            counts: dict[int, int] = {}
            for entry in ingests:
                class_uid = FORMAT_CLASS_MAP.get(entry.source_format)
                if class_uid is None:
                    continue
                counts[class_uid] = counts.get(class_uid, 0) + (
                    entry.event_count or 0
                )

            sorted_counts = sorted(
                counts.items(), key=lambda x: x[1], reverse=True
            )
            return sorted_counts[:limit]
        except Exception:
            return []