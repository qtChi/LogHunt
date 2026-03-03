# ==============================================================================
# loghunter/schema/audit_models.py
#
# Audit entry data classes used by AuditLogger.
#
# Per spec sections 24 and 29 — these are the typed containers passed to
# AuditLogger.log_query, log_ingest, and log_rule_event.
#
# All fields use simple Python types so they serialise cleanly to SQLite
# without an ORM. Dataclasses are frozen=False here because AuditLogger
# populates some fields (e.g. executed_at) after construction.
# ==============================================================================

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def _now_utc() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class QueryAuditEntry:
    """
    Records a single query execution attempt.

    Attributes:
        session_id:     Analyst session identifier.
        sql_template:   Parameterised SQL that was executed.
        event_class:    OCSF class_uid queried, or None.
        success:        True if query executed without error.
        row_count:      Number of rows returned, or None on failure.
        latency_ms:     Query execution time in milliseconds, or None.
        failure_reason: Error description if success=False, else None.
        executed_at:    UTC timestamp string of execution.
    """
    session_id: str
    sql_template: str
    event_class: Optional[int] = None
    success: bool = True
    row_count: Optional[int] = None
    latency_ms: Optional[float] = None
    failure_reason: Optional[str] = None
    executed_at: str = field(default_factory=_now_utc)


@dataclass
class IngestAuditEntry:
    """
    Records a single ingest batch.

    Attributes:
        ingest_id:    Unique identifier for this ingest operation.
        source_format: Log format parsed e.g. "zeek_conn", "evtx".
        event_count:  Number of events successfully normalised.
        failed_count: Number of raw events that failed normalisation.
        file_path:    Source file path, or None if not file-based.
        ingested_at:  UTC timestamp string of ingest completion.
    """
    ingest_id: str
    source_format: str
    event_count: int = 0
    failed_count: int = 0
    file_path: Optional[str] = None
    ingested_at: str = field(default_factory=_now_utc)


@dataclass
class RuleAuditEntry:
    """
    Records a single rule lifecycle event.

    Attributes:
        rule_id:     UUID of the rule.
        event_type:  One of: created, confirmed, updated, exported,
                     backtested, deleted.
        session_id:  Analyst session identifier, or None.
        detail:      Free-text detail string, or None.
        occurred_at: UTC timestamp string.
    """
    rule_id: str
    event_type: str
    session_id: Optional[str] = None
    detail: Optional[str] = None
    occurred_at: str = field(default_factory=_now_utc)