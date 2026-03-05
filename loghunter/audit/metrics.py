from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from loghunter.audit.logger import AuditLogger

FORMAT_CLASS_MAP: dict[str, int] = {
    "zeek":   3001,
    "apache": 3002,
    "evtx":   6003,
    "syslog": 1001,
}

@dataclass
class SystemMetrics:
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
    def __init__(self, audit_logger: AuditLogger) -> None:
        if audit_logger is None:
            raise TypeError("audit_logger must not be None")
        self._logger = audit_logger

    def get_system_metrics(self, rules_stored: int = 0, rules_confirmed: int = 0) -> SystemMetrics:
        try:
            queries = self._read_queries()
            ingests = self._read_ingests()
            total_q = len(queries)
            successful = sum(1 for q in queries if q.get("success"))
            latencies = [float(q["latency_ms"]) for q in queries if q.get("success") and q.get("latency_ms") is not None]
            avg_latency = sum(latencies) / len(latencies) if latencies else None
            total_events = sum(int(i.get("event_count") or 0) for i in ingests)
            return SystemMetrics(
                total_queries=total_q,
                successful_queries=successful,
                failed_queries=total_q - successful,
                total_ingest_events=total_events,
                total_ingest_runs=len(ingests),
                rules_stored=rules_stored,
                rules_confirmed=rules_confirmed,
                avg_query_latency_ms=avg_latency,
                last_ingest_at=ingests[0]["ingested_at"] if ingests else None,
                last_query_at=queries[0]["executed_at"] if queries else None,
            )
        except Exception:
            return SystemMetrics(rules_stored=rules_stored, rules_confirmed=rules_confirmed)

    def get_query_success_rate(self) -> float:
        try:
            queries = self._read_queries()
            if not queries:
                return 0.0
            return sum(1 for q in queries if q.get("success")) / len(queries) * 100.0
        except Exception:
            return 0.0

    def get_top_event_classes(self, limit: int = 5) -> list[tuple[int, int]]:
        if limit < 1:
            raise ValueError(f"limit must be >= 1, got {limit}")
        try:
            ingests = self._read_ingests()
            if not ingests:
                return []
            counts: dict[int, int] = {}
            for row in ingests:
                fmt = str(row.get("source_format") or "").lower()
                class_uid = FORMAT_CLASS_MAP.get(fmt)
                if class_uid is not None:
                    counts[class_uid] = counts.get(class_uid, 0) + int(row.get("event_count") or 0)
            return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        except Exception:
            return []

    def _read_queries(self) -> list[dict]:
        try:
            rows = self._logger._db.execute_read(
                "SELECT executed_at, success, latency_ms FROM query_audit ORDER BY executed_at DESC LIMIT 10000", ()
            )
            return [dict(r) for r in rows]
        except Exception:
            return []

    def _read_ingests(self) -> list[dict]:
        try:
            rows = self._logger._db.execute_read(
                "SELECT ingested_at, source_format, event_count FROM ingest_audit ORDER BY ingested_at DESC LIMIT 10000", ()
            )
            return [dict(r) for r in rows]
        except Exception:
            return []