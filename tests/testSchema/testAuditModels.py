# ==============================================================================
# tests/testSchema/testAuditModels.py
#
# Tests for loghunter/schema/audit_models.py
#
# Coverage strategy — every branch and default explicitly targeted:
#
# _now_utc:
#   Returns a non-empty ISO 8601 string
#   Returns a UTC-based timestamp
#
# QueryAuditEntry:
#   Default factory sets executed_at
#   All fields settable post-construction (mutable dataclass)
#   Default values correct for optional fields
#   Explicit values stored correctly
#
# IngestAuditEntry:
#   Default factory sets ingested_at
#   Default counts are zero
#   All fields stored correctly
#
# RuleAuditEntry:
#   Default factory sets occurred_at
#   Default session_id and detail are None
#   All fields stored correctly
# ==============================================================================

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from loghunter.schema.audit_models import (
    IngestAuditEntry,
    QueryAuditEntry,
    RuleAuditEntry,
    _now_utc,
)


# ==============================================================================
# TestNowUtc
# ==============================================================================

class TestNowUtc:

    def test_returns_non_empty_string(self):
        result = _now_utc()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_format_is_iso_8601(self):
        result = _now_utc()
        # Must parse without error as UTC datetime
        dt = datetime.strptime(result, "%Y-%m-%dT%H:%M:%SZ")
        assert dt is not None

    def test_two_calls_return_strings(self):
        a = _now_utc()
        b = _now_utc()
        assert isinstance(a, str)
        assert isinstance(b, str)


# ==============================================================================
# TestQueryAuditEntry
# ==============================================================================

class TestQueryAuditEntry:

    def test_minimal_construction(self):
        entry = QueryAuditEntry(
            session_id="s1",
            sql_template="SELECT 1",
        )
        assert entry.session_id == "s1"
        assert entry.sql_template == "SELECT 1"

    def test_default_success_is_true(self):
        entry = QueryAuditEntry(session_id="s", sql_template="SELECT 1")
        assert entry.success is True

    def test_default_event_class_is_none(self):
        entry = QueryAuditEntry(session_id="s", sql_template="SELECT 1")
        assert entry.event_class is None

    def test_default_row_count_is_none(self):
        entry = QueryAuditEntry(session_id="s", sql_template="SELECT 1")
        assert entry.row_count is None

    def test_default_latency_ms_is_none(self):
        entry = QueryAuditEntry(session_id="s", sql_template="SELECT 1")
        assert entry.latency_ms is None

    def test_default_failure_reason_is_none(self):
        entry = QueryAuditEntry(session_id="s", sql_template="SELECT 1")
        assert entry.failure_reason is None

    def test_default_executed_at_is_set_by_factory(self):
        entry = QueryAuditEntry(session_id="s", sql_template="SELECT 1")
        assert entry.executed_at is not None
        assert len(entry.executed_at) > 0

    def test_explicit_values_stored_correctly(self):
        entry = QueryAuditEntry(
            session_id="sess",
            sql_template="SELECT * FROM logs",
            event_class=6003,
            success=False,
            row_count=0,
            latency_ms=12.5,
            failure_reason="timeout",
            executed_at="2026-01-01T00:00:00Z",
        )
        assert entry.session_id == "sess"
        assert entry.sql_template == "SELECT * FROM logs"
        assert entry.event_class == 6003
        assert entry.success is False
        assert entry.row_count == 0
        assert entry.latency_ms == 12.5
        assert entry.failure_reason == "timeout"
        assert entry.executed_at == "2026-01-01T00:00:00Z"

    def test_is_mutable(self):
        entry = QueryAuditEntry(session_id="s", sql_template="SELECT 1")
        entry.success = False
        entry.row_count = 5
        assert entry.success is False
        assert entry.row_count == 5

    def test_two_entries_independent_executed_at(self):
        # Each entry gets its own default_factory call
        a = QueryAuditEntry(session_id="a", sql_template="SELECT 1")
        b = QueryAuditEntry(session_id="b", sql_template="SELECT 1")
        # Both are strings — factory called independently
        assert isinstance(a.executed_at, str)
        assert isinstance(b.executed_at, str)


# ==============================================================================
# TestIngestAuditEntry
# ==============================================================================

class TestIngestAuditEntry:

    def test_minimal_construction(self):
        entry = IngestAuditEntry(ingest_id="i1", source_format="zeek")
        assert entry.ingest_id == "i1"
        assert entry.source_format == "zeek"

    def test_default_event_count_is_zero(self):
        entry = IngestAuditEntry(ingest_id="i", source_format="zeek")
        assert entry.event_count == 0

    def test_default_failed_count_is_zero(self):
        entry = IngestAuditEntry(ingest_id="i", source_format="zeek")
        assert entry.failed_count == 0

    def test_default_file_path_is_none(self):
        entry = IngestAuditEntry(ingest_id="i", source_format="zeek")
        assert entry.file_path is None

    def test_default_ingested_at_is_set_by_factory(self):
        entry = IngestAuditEntry(ingest_id="i", source_format="zeek")
        assert entry.ingested_at is not None
        assert len(entry.ingested_at) > 0

    def test_explicit_values_stored_correctly(self):
        entry = IngestAuditEntry(
            ingest_id="i2",
            source_format="evtx",
            event_count=500,
            failed_count=10,
            file_path="/logs/security.evtx",
            ingested_at="2026-03-01T00:00:00Z",
        )
        assert entry.ingest_id == "i2"
        assert entry.source_format == "evtx"
        assert entry.event_count == 500
        assert entry.failed_count == 10
        assert entry.file_path == "/logs/security.evtx"
        assert entry.ingested_at == "2026-03-01T00:00:00Z"

    def test_is_mutable(self):
        entry = IngestAuditEntry(ingest_id="i", source_format="zeek")
        entry.event_count = 42
        assert entry.event_count == 42


# ==============================================================================
# TestRuleAuditEntry
# ==============================================================================

class TestRuleAuditEntry:

    def test_minimal_construction(self):
        entry = RuleAuditEntry(rule_id="r1", event_type="created")
        assert entry.rule_id == "r1"
        assert entry.event_type == "created"

    def test_default_session_id_is_none(self):
        entry = RuleAuditEntry(rule_id="r", event_type="created")
        assert entry.session_id is None

    def test_default_detail_is_none(self):
        entry = RuleAuditEntry(rule_id="r", event_type="created")
        assert entry.detail is None

    def test_default_occurred_at_is_set_by_factory(self):
        entry = RuleAuditEntry(rule_id="r", event_type="created")
        assert entry.occurred_at is not None
        assert len(entry.occurred_at) > 0

    def test_explicit_values_stored_correctly(self):
        entry = RuleAuditEntry(
            rule_id="rule-uuid",
            event_type="confirmed",
            session_id="sess-42",
            detail="Analyst approved after review",
            occurred_at="2026-05-01T12:00:00Z",
        )
        assert entry.rule_id == "rule-uuid"
        assert entry.event_type == "confirmed"
        assert entry.session_id == "sess-42"
        assert entry.detail == "Analyst approved after review"
        assert entry.occurred_at == "2026-05-01T12:00:00Z"

    def test_all_event_types_storable(self):
        for event_type in ("created", "confirmed", "updated",
                           "exported", "backtested", "deleted"):
            entry = RuleAuditEntry(rule_id="r", event_type=event_type)
            assert entry.event_type == event_type

    def test_is_mutable(self):
        entry = RuleAuditEntry(rule_id="r", event_type="created")
        entry.detail = "updated detail"
        assert entry.detail == "updated detail"