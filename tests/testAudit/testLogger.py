# ==============================================================================
# tests/testAudit/testLogger.py
#
# Tests for loghunter/audit/logger.py
#
# Coverage strategy — every branch explicitly targeted:
#
# Constructor:
#   None sqlite_layer → TypeError
#   Valid layer → constructs
#
# log_query:
#   None entry → TypeError
#   Write failure → logs to stderr, does NOT raise
#   Valid entry → persisted and retrievable
#   success=False stored correctly as 0
#
# log_ingest:
#   None entry → TypeError
#   Valid entry → persisted and retrievable
#
# log_rule_event:
#   None entry → TypeError
#   Valid entry → persisted and retrievable
#
# get_query_history:
#   limit < 1 → ValueError
#   No entries → empty list
#   session_id=None → all entries up to limit
#   session_id provided → filtered entries only
#   limit respected
#   Returns QueryAuditEntry objects
#   Most recent first ordering
#
# get_ingest_history:
#   limit < 1 → ValueError
#   No entries → empty list
#   Returns IngestAuditEntry objects
#   limit respected
#   Most recent first ordering
#
# audit_models:
#   QueryAuditEntry default factory sets executed_at
#   IngestAuditEntry default factory sets ingested_at
#   RuleAuditEntry default factory sets occurred_at
# ==============================================================================

from __future__ import annotations

import sys

import pytest

from loghunter.audit.logger import AuditLogger
from loghunter.engine.sqlite_layer import SQLiteLayer
from loghunter.schema.audit_models import (
    IngestAuditEntry,
    QueryAuditEntry,
    RuleAuditEntry,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_layer(tmp_path) -> SQLiteLayer:
    return SQLiteLayer(str(tmp_path / "test.db"))


def _make_query_entry(**overrides) -> QueryAuditEntry:
    defaults = dict(
        session_id="sess-001",
        sql_template="SELECT * FROM logs",
        event_class=6003,
        success=True,
        row_count=10,
        latency_ms=5.0,
        failure_reason=None,
        executed_at="2026-01-01T00:00:00Z",
    )
    defaults.update(overrides)
    return QueryAuditEntry(**defaults)


def _make_ingest_entry(**overrides) -> IngestAuditEntry:
    defaults = dict(
        ingest_id="ingest-001",
        source_format="zeek_conn",
        event_count=100,
        failed_count=2,
        file_path="/data/conn.log",
        ingested_at="2026-01-01T00:00:00Z",
    )
    defaults.update(overrides)
    return IngestAuditEntry(**defaults)


def _make_rule_entry(**overrides) -> RuleAuditEntry:
    defaults = dict(
        rule_id="rule-uuid-001",
        event_type="created",
        session_id="sess-001",
        detail="Initial creation",
        occurred_at="2026-01-01T00:00:00Z",
    )
    defaults.update(overrides)
    return RuleAuditEntry(**defaults)


# ==============================================================================
# TestAuditLoggerConstructor
# ==============================================================================

class TestAuditLoggerConstructor:

    def test_none_layer_raises_type_error(self):
        with pytest.raises(TypeError):
            AuditLogger(None)

    def test_valid_layer_constructs(self, tmp_path):
        layer = _make_layer(tmp_path)
        logger = AuditLogger(layer)
        assert logger is not None
        layer.close()

    def test_uses_provided_sqlite_layer(self, tmp_path):
        layer = _make_layer(tmp_path)
        logger = AuditLogger(layer)
        assert logger._db is layer
        layer.close()


# ==============================================================================
# TestLogQuery
# ==============================================================================

class TestLogQuery:

    def test_none_entry_raises_type_error(self, audit_logger):
        with pytest.raises(TypeError):
            audit_logger.log_query(None)

    def test_valid_entry_is_persisted(self, audit_logger):
        entry = _make_query_entry(session_id="test-sess")
        audit_logger.log_query(entry)
        rows = audit_logger._db.execute_read(
            "SELECT * FROM query_audit WHERE session_id = ?", ("test-sess",)
        )
        assert len(rows) == 1

    def test_all_fields_stored_correctly(self, audit_logger):
        entry = _make_query_entry(
            session_id="s1",
            sql_template="SELECT 1",
            event_class=4001,
            success=True,
            row_count=5,
            latency_ms=12.5,
            failure_reason=None,
            executed_at="2026-06-01T00:00:00Z",
        )
        audit_logger.log_query(entry)
        rows = audit_logger._db.execute_read(
            "SELECT * FROM query_audit WHERE session_id = ?", ("s1",)
        )
        r = rows[0]
        assert r["sql_template"] == "SELECT 1"
        assert r["event_class"] == 4001
        assert r["success"] == 1
        assert r["row_count"] == 5
        assert r["latency_ms"] == 12.5
        assert r["failure_reason"] is None

    def test_success_false_stored_as_zero(self, audit_logger):
        entry = _make_query_entry(success=False, failure_reason="timeout")
        audit_logger.log_query(entry)
        rows = audit_logger._db.execute_read(
            "SELECT success FROM query_audit", ()
        )
        assert rows[0]["success"] == 0

    def test_write_failure_logs_to_stderr_does_not_raise(
        self, tmp_path, capsys
    ):
        # Close the layer to force a write failure
        layer = _make_layer(tmp_path)
        logger = AuditLogger(layer)
        layer.close()
        entry = _make_query_entry()
        # Must NOT raise
        logger.log_query(entry)
        captured = capsys.readouterr()
        assert "AuditLogger.log_query write failure" in captured.err

    def test_multiple_entries_all_persisted(self, audit_logger):
        for i in range(5):
            audit_logger.log_query(
                _make_query_entry(session_id=f"s{i}")
            )
        rows = audit_logger._db.execute_read(
            "SELECT * FROM query_audit", ()
        )
        assert len(rows) == 5


# ==============================================================================
# TestLogIngest
# ==============================================================================

class TestLogIngest:

    def test_none_entry_raises_type_error(self, audit_logger):
        with pytest.raises(TypeError):
            audit_logger.log_ingest(None)

    def test_valid_entry_is_persisted(self, audit_logger):
        entry = _make_ingest_entry(ingest_id="ingest-xyz")
        audit_logger.log_ingest(entry)
        rows = audit_logger._db.execute_read(
            "SELECT * FROM ingest_audit WHERE ingest_id = ?", ("ingest-xyz",)
        )
        assert len(rows) == 1

    def test_all_fields_stored_correctly(self, audit_logger):
        entry = _make_ingest_entry(
            ingest_id="i1",
            source_format="evtx",
            event_count=50,
            failed_count=3,
            file_path="/logs/security.evtx",
            ingested_at="2026-03-01T00:00:00Z",
        )
        audit_logger.log_ingest(entry)
        rows = audit_logger._db.execute_read(
            "SELECT * FROM ingest_audit WHERE ingest_id = ?", ("i1",)
        )
        r = rows[0]
        assert r["source_format"] == "evtx"
        assert r["event_count"] == 50
        assert r["failed_count"] == 3
        assert r["file_path"] == "/logs/security.evtx"

    def test_null_file_path_stored_as_none(self, audit_logger):
        entry = _make_ingest_entry(file_path=None)
        audit_logger.log_ingest(entry)
        rows = audit_logger._db.execute_read(
            "SELECT * FROM ingest_audit", ()
        )
        assert rows[0]["file_path"] is None


# ==============================================================================
# TestLogRuleEvent
# ==============================================================================

class TestLogRuleEvent:

    def test_none_entry_raises_type_error(self, audit_logger):
        with pytest.raises(TypeError):
            audit_logger.log_rule_event(None)

    def test_valid_entry_is_persisted(self, audit_logger):
        entry = _make_rule_entry(rule_id="rule-abc")
        audit_logger.log_rule_event(entry)
        rows = audit_logger._db.execute_read(
            "SELECT * FROM rule_audit WHERE rule_id = ?", ("rule-abc",)
        )
        assert len(rows) == 1

    def test_all_fields_stored_correctly(self, audit_logger):
        entry = _make_rule_entry(
            rule_id="r1",
            event_type="confirmed",
            session_id="sess-99",
            detail="Analyst approved",
            occurred_at="2026-05-01T00:00:00Z",
        )
        audit_logger.log_rule_event(entry)
        rows = audit_logger._db.execute_read(
            "SELECT * FROM rule_audit WHERE rule_id = ?", ("r1",)
        )
        r = rows[0]
        assert r["event_type"] == "confirmed"
        assert r["session_id"] == "sess-99"
        assert r["detail"] == "Analyst approved"

    def test_null_session_and_detail_stored_as_none(self, audit_logger):
        entry = _make_rule_entry(session_id=None, detail=None)
        audit_logger.log_rule_event(entry)
        rows = audit_logger._db.execute_read(
            "SELECT * FROM rule_audit", ()
        )
        assert rows[0]["session_id"] is None
        assert rows[0]["detail"] is None


# ==============================================================================
# TestGetQueryHistory
# ==============================================================================

class TestGetQueryHistory:

    def test_limit_zero_raises_value_error(self, audit_logger):
        with pytest.raises(ValueError):
            audit_logger.get_query_history(limit=0)

    def test_negative_limit_raises_value_error(self, audit_logger):
        with pytest.raises(ValueError):
            audit_logger.get_query_history(limit=-1)

    def test_no_entries_returns_empty_list(self, audit_logger):
        result = audit_logger.get_query_history()
        assert result == []

    def test_returns_list_of_query_audit_entries(self, audit_logger):
        audit_logger.log_query(_make_query_entry())
        result = audit_logger.get_query_history()
        assert all(isinstance(e, QueryAuditEntry) for e in result)

    def test_session_id_filter_returns_only_matching(self, audit_logger):
        audit_logger.log_query(_make_query_entry(session_id="s-alpha"))
        audit_logger.log_query(_make_query_entry(session_id="s-beta"))
        result = audit_logger.get_query_history(session_id="s-alpha")
        assert all(e.session_id == "s-alpha" for e in result)
        assert len(result) == 1

    def test_no_session_filter_returns_all(self, audit_logger):
        for i in range(3):
            audit_logger.log_query(_make_query_entry(session_id=f"s{i}"))
        result = audit_logger.get_query_history()
        assert len(result) == 3

    def test_limit_respected(self, audit_logger):
        for i in range(10):
            audit_logger.log_query(_make_query_entry(session_id=f"s{i}"))
        result = audit_logger.get_query_history(limit=3)
        assert len(result) == 3

    def test_most_recent_first_ordering(self, audit_logger):
        audit_logger.log_query(_make_query_entry(
            session_id="first", executed_at="2026-01-01T00:00:00Z"
        ))
        audit_logger.log_query(_make_query_entry(
            session_id="second", executed_at="2026-06-01T00:00:00Z"
        ))
        result = audit_logger.get_query_history()
        assert result[0].session_id == "second"

    def test_session_filter_with_limit(self, audit_logger):
        for i in range(5):
            audit_logger.log_query(_make_query_entry(session_id="same"))
        result = audit_logger.get_query_history(session_id="same", limit=2)
        assert len(result) == 2

    def test_entry_fields_round_trip_correctly(self, audit_logger):
        entry = _make_query_entry(
            session_id="roundtrip",
            sql_template="SELECT 1",
            event_class=3001,
            success=False,
            row_count=0,
            latency_ms=99.9,
            failure_reason="timeout",
        )
        audit_logger.log_query(entry)
        result = audit_logger.get_query_history(session_id="roundtrip")
        r = result[0]
        assert r.session_id == "roundtrip"
        assert r.sql_template == "SELECT 1"
        assert r.event_class == 3001
        assert r.success is False
        assert r.row_count == 0
        assert r.latency_ms == 99.9
        assert r.failure_reason == "timeout"


# ==============================================================================
# TestGetIngestHistory
# ==============================================================================

class TestGetIngestHistory:

    def test_limit_zero_raises_value_error(self, audit_logger):
        with pytest.raises(ValueError):
            audit_logger.get_ingest_history(limit=0)

    def test_negative_limit_raises_value_error(self, audit_logger):
        with pytest.raises(ValueError):
            audit_logger.get_ingest_history(limit=-1)

    def test_no_entries_returns_empty_list(self, audit_logger):
        assert audit_logger.get_ingest_history() == []

    def test_returns_list_of_ingest_audit_entries(self, audit_logger):
        audit_logger.log_ingest(_make_ingest_entry())
        result = audit_logger.get_ingest_history()
        assert all(isinstance(e, IngestAuditEntry) for e in result)

    def test_limit_respected(self, audit_logger):
        for i in range(10):
            audit_logger.log_ingest(_make_ingest_entry(ingest_id=f"i{i}"))
        result = audit_logger.get_ingest_history(limit=4)
        assert len(result) == 4

    def test_most_recent_first(self, audit_logger):
        audit_logger.log_ingest(_make_ingest_entry(
            ingest_id="first", ingested_at="2026-01-01T00:00:00Z"
        ))
        audit_logger.log_ingest(_make_ingest_entry(
            ingest_id="second", ingested_at="2026-06-01T00:00:00Z"
        ))
        result = audit_logger.get_ingest_history()
        assert result[0].ingest_id == "second"

    def test_entry_fields_round_trip_correctly(self, audit_logger):
        entry = _make_ingest_entry(
            ingest_id="rt1",
            source_format="syslog",
            event_count=200,
            failed_count=5,
            file_path="/var/log/syslog",
        )
        audit_logger.log_ingest(entry)
        result = audit_logger.get_ingest_history()
        r = result[0]
        assert r.ingest_id == "rt1"
        assert r.source_format == "syslog"
        assert r.event_count == 200
        assert r.failed_count == 5
        assert r.file_path == "/var/log/syslog"


# ==============================================================================
# TestAuditModels
# ==============================================================================

class TestAuditModels:

    def test_query_entry_default_executed_at_is_set(self):
        entry = QueryAuditEntry(session_id="s", sql_template="SELECT 1")
        assert entry.executed_at is not None
        assert len(entry.executed_at) > 0

    def test_ingest_entry_default_ingested_at_is_set(self):
        entry = IngestAuditEntry(ingest_id="i", source_format="zeek")
        assert entry.ingested_at is not None

    def test_rule_entry_default_occurred_at_is_set(self):
        entry = RuleAuditEntry(rule_id="r", event_type="created")
        assert entry.occurred_at is not None

    def test_query_entry_is_mutable(self):
        entry = QueryAuditEntry(session_id="s", sql_template="SELECT 1")
        entry.success = False
        assert entry.success is False

    def test_ingest_entry_default_counts_zero(self):
        entry = IngestAuditEntry(ingest_id="i", source_format="evtx")
        assert entry.event_count == 0
        assert entry.failed_count == 0