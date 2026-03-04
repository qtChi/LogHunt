"""
tests/testEngine/testQueryBuilder.py
Tests for loghunter.engine.query_builder.QueryBuilder
Target: 100% branch coverage
"""
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from loghunter.engine.query_builder import QueryBuilder, _escape_string
from loghunter.exceptions import PartitionNotFoundError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_duckdb():
    m = MagicMock()
    m.get_available_partitions.return_value = [6003, 4001, 3001]
    m.execute_query.return_value = []
    return m


@pytest.fixture
def mock_registry():
    m = MagicMock()
    m.is_valid_field.return_value = True
    return m


@pytest.fixture
def mock_audit():
    return MagicMock()


@pytest.fixture
def qb(mock_duckdb, mock_registry, mock_audit):
    return QueryBuilder(mock_duckdb, mock_registry, mock_audit)


# ---------------------------------------------------------------------------
# __init__ — TypeError guards
# ---------------------------------------------------------------------------

class TestInit:
    def test_none_duckdb_raises(self, mock_registry, mock_audit):
        with pytest.raises(TypeError):
            QueryBuilder(None, mock_registry, mock_audit)

    def test_none_registry_raises(self, mock_duckdb, mock_audit):
        with pytest.raises(TypeError):
            QueryBuilder(mock_duckdb, None, mock_audit)

    def test_none_audit_raises(self, mock_duckdb, mock_registry):
        with pytest.raises(TypeError):
            QueryBuilder(mock_duckdb, mock_registry, None)

    def test_valid_construction(self, mock_duckdb, mock_registry, mock_audit):
        qb = QueryBuilder(mock_duckdb, mock_registry, mock_audit)
        assert qb is not None


# ---------------------------------------------------------------------------
# build_sql
# ---------------------------------------------------------------------------

class TestBuildSql:
    def test_none_class_uid_raises(self, qb):
        with pytest.raises(TypeError):
            qb.build_sql(None)

    def test_unknown_partition_raises(self, qb, mock_duckdb):
        mock_duckdb.get_available_partitions.return_value = []
        with pytest.raises(PartitionNotFoundError):
            qb.build_sql(6003)

    def test_no_filters_no_time(self, qb):
        sql = qb.build_sql(6003)
        assert "{partition}" in sql
        assert "WHERE" not in sql
        assert "SELECT *" in sql

    def test_time_range_adds_where(self, qb):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end = datetime(2026, 1, 2, tzinfo=timezone.utc)
        sql = qb.build_sql(6003, time_range=(start, end))
        assert "WHERE" in sql
        assert "time >=" in sql
        assert "time <=" in sql

    def test_filters_valid_field(self, qb, mock_registry):
        mock_registry.is_valid_field.return_value = True
        sql = qb.build_sql(6003, filters={"activity_id": 1})
        assert "activity_id = 1" in sql

    def test_filters_invalid_field_dropped(self, qb, mock_registry):
        mock_registry.is_valid_field.return_value = False
        sql = qb.build_sql(6003, filters={"bad_field": "x"})
        assert "bad_field" not in sql
        assert "WHERE" not in sql

    def test_string_filter_quoted(self, qb, mock_registry):
        mock_registry.is_valid_field.return_value = True
        sql = qb.build_sql(6003, filters={"actor.user.name": "alice"})
        assert "'alice'" in sql

    def test_string_filter_quote_escaped(self, qb, mock_registry):
        mock_registry.is_valid_field.return_value = True
        sql = qb.build_sql(6003, filters={"actor.user.name": "O'Brien"})
        assert "O''Brien" in sql

    def test_bool_filter_true(self, qb, mock_registry):
        mock_registry.is_valid_field.return_value = True
        sql = qb.build_sql(6003, filters={"some_flag": True})
        assert "= 1" in sql

    def test_bool_filter_false(self, qb, mock_registry):
        mock_registry.is_valid_field.return_value = True
        sql = qb.build_sql(6003, filters={"some_flag": False})
        assert "= 0" in sql

    def test_float_filter(self, qb, mock_registry):
        mock_registry.is_valid_field.return_value = True
        sql = qb.build_sql(6003, filters={"network.bytes_out": 9999.5})
        assert "9999.5" in sql

    def test_none_filter_value_is_null(self, qb, mock_registry):
        mock_registry.is_valid_field.return_value = True
        sql = qb.build_sql(6003, filters={"actor.user.name": None})
        assert "IS NULL" in sql

    def test_multiple_conditions_joined(self, qb, mock_registry):
        mock_registry.is_valid_field.return_value = True
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end = datetime(2026, 1, 2, tzinfo=timezone.utc)
        sql = qb.build_sql(
            6003,
            filters={"activity_id": 2},
            time_range=(start, end),
        )
        assert sql.count("AND") >= 2


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------

class TestExecute:
    def test_none_class_uid_raises(self, qb):
        with pytest.raises(TypeError):
            qb.execute(None)

    def test_partition_not_found_raises_and_audits(self, qb, mock_duckdb, mock_audit):
        mock_duckdb.get_available_partitions.return_value = []
        with pytest.raises(PartitionNotFoundError):
            qb.execute(6003)
        mock_audit.log_query.assert_called_once()
        entry = mock_audit.log_query.call_args[0][0]
        assert entry.success is False

    def test_empty_result_returns_empty_list(self, qb, mock_duckdb, mock_audit):
        mock_duckdb.execute_query.return_value = []
        events = qb.execute(6003)
        assert events == []
        mock_audit.log_query.assert_called_once()
        entry = mock_audit.log_query.call_args[0][0]
        assert entry.success is True
        assert entry.row_count == 0

    def test_include_replay_hardcoded_false(self, qb, mock_duckdb):
        qb.execute(6003)
        call_kwargs = mock_duckdb.execute_query.call_args
        assert call_kwargs[1].get("include_replay") is False or \
               (call_kwargs[0] and call_kwargs[0][2] is False) or \
               mock_duckdb.execute_query.call_args[1].get("include_replay", False) is False

    def test_valid_row_converted_to_event(self, qb, mock_duckdb, mock_registry):
        row = {
            "class_uid": 6003,
            "activity_id": 1,
            "severity_id": 1,
            "time": "2026-01-01T00:00:00",
            "metadata.log_source": "evtx",
            "metadata.original_time": "2026-01-01T00:00:00Z",
        }
        mock_duckdb.execute_query.return_value = [row]
        mock_registry.is_valid_field.return_value = False  # no extra kwargs

        # Patch OCSFEvent construction to avoid needing real registry
        with patch("loghunter.engine.query_builder.OCSFEvent") as MockEvent:
            mock_instance = MagicMock()
            MockEvent.return_value = mock_instance
            events = qb.execute(6003)
        assert len(events) == 1

    def test_bad_row_silently_skipped(self, qb, mock_duckdb):
        # Row missing all required fields — _row_to_event returns None
        mock_duckdb.execute_query.return_value = [{"junk": "data"}]
        with patch(
            "loghunter.engine.query_builder.QueryBuilder._row_to_event",
            return_value=None,
        ):
            events = qb.execute(6003)
        assert events == []

    def test_audit_latency_populated(self, qb, mock_duckdb, mock_audit):
        mock_duckdb.execute_query.return_value = []
        qb.execute(6003)
        entry = mock_audit.log_query.call_args[0][0]
        assert entry.latency_ms is not None
        assert entry.latency_ms >= 0


# ---------------------------------------------------------------------------
# _parse_time
# ---------------------------------------------------------------------------

class TestParseTime:
    def test_aware_datetime_returned_as_is(self):
        dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
        result = QueryBuilder._parse_time(dt)
        assert result.tzinfo is not None

    def test_naive_datetime_gets_utc(self):
        dt = datetime(2026, 1, 1)
        result = QueryBuilder._parse_time(dt)
        assert result.tzinfo == timezone.utc

    def test_none_returns_now_utc(self):
        result = QueryBuilder._parse_time(None)
        assert result.tzinfo is not None

    def test_iso_string_parsed(self):
        result = QueryBuilder._parse_time("2026-01-01T12:00:00")
        assert result.year == 2026
        assert result.tzinfo == timezone.utc

    def test_invalid_string_returns_now(self):
        result = QueryBuilder._parse_time("not-a-date")
        assert result.tzinfo is not None


# ---------------------------------------------------------------------------
# _safe_int
# ---------------------------------------------------------------------------

class TestSafeInt:
    def test_none_returns_zero(self):
        assert QueryBuilder._safe_int(None) == 0

    def test_int_returned(self):
        assert QueryBuilder._safe_int(3) == 3

    def test_string_int_converted(self):
        assert QueryBuilder._safe_int("7") == 7

    def test_bad_string_returns_zero(self):
        assert QueryBuilder._safe_int("xyz") == 0


# ---------------------------------------------------------------------------
# _escape_string
# ---------------------------------------------------------------------------

class TestEscapeString:
    def test_no_quotes(self):
        assert _escape_string("hello") == "hello"

    def test_single_quote_doubled(self):
        assert _escape_string("O'Brien") == "O''Brien"

    def test_multiple_quotes(self):
        assert _escape_string("it's Alice's") == "it''s Alice''s"