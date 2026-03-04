"""
tests/testEngine/testSigmaEngine.py
Tests for loghunter.engine.sigma_engine — SigmaEngine + BacktestResult
Target: 100% branch coverage
"""
import pytest
from unittest.mock import MagicMock, call, patch

from loghunter.engine.sigma_engine import BacktestResult, SigmaEngine, _sha256, _event_matches_rule
from loghunter.exceptions import RuleNotConfirmedError, RuleNotFoundError


_YAML = "title: Test Rule\ndetection:\n  keywords:\n    - malware\n  condition: keywords\n"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_db():
    m = MagicMock()
    m.execute_read.return_value = []
    return m


@pytest.fixture
def mock_audit():
    return MagicMock()


@pytest.fixture
def mock_duckdb():
    m = MagicMock()
    m.get_available_partitions.return_value = [6003]
    m.execute_query.return_value = []
    return m


@pytest.fixture
def engine(mock_db, mock_audit):
    return SigmaEngine(mock_db, mock_audit)


@pytest.fixture
def engine_with_duckdb(mock_db, mock_audit, mock_duckdb):
    return SigmaEngine(mock_db, mock_audit, duckdb_layer=mock_duckdb)


# ---------------------------------------------------------------------------
# BacktestResult
# ---------------------------------------------------------------------------

class TestBacktestResult:
    def test_defaults(self):
        r = BacktestResult(rule_id="r1", session_id="s1")
        assert r.match_count == 0
        assert r.total_events == 0
        assert r.matched_events == []
        assert r.executed_at.endswith("Z")


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------

class TestInit:
    def test_none_sqlite_raises(self, mock_audit):
        with pytest.raises(TypeError):
            SigmaEngine(None, mock_audit)

    def test_none_audit_raises(self, mock_db):
        with pytest.raises(TypeError):
            SigmaEngine(mock_db, None)

    def test_duckdb_optional(self, mock_db, mock_audit):
        engine = SigmaEngine(mock_db, mock_audit, duckdb_layer=None)
        assert engine is not None

    def test_valid_construction(self, mock_db, mock_audit, mock_duckdb):
        engine = SigmaEngine(mock_db, mock_audit, duckdb_layer=mock_duckdb)
        assert engine is not None


# ---------------------------------------------------------------------------
# store_rule
# ---------------------------------------------------------------------------

class TestStoreRule:
    def test_none_rule_id_raises(self, engine):
        with pytest.raises(TypeError):
            engine.store_rule(None, _YAML)

    def test_none_yaml_raises(self, engine):
        with pytest.raises(TypeError):
            engine.store_rule("r1", None)

    def test_empty_rule_id_raises(self, engine):
        with pytest.raises(ValueError):
            engine.store_rule("  ", _YAML)

    def test_empty_yaml_raises(self, engine):
        with pytest.raises(ValueError):
            engine.store_rule("r1", "  ")

    def test_new_rule_inserts_version_1(self, engine, mock_db):
        mock_db.execute_read.return_value = []  # not found
        engine.store_rule("r1", _YAML)
        sql, params = mock_db.execute_write.call_args[0]
        assert "INSERT INTO rules" in sql
        assert ", 1, 0," in sql  # version hardcoded in SQL literal

    def test_new_rule_logs_created(self, engine, mock_db, mock_audit):
        mock_db.execute_read.return_value = []
        engine.store_rule("r1", _YAML)
        entry = mock_audit.log_rule_event.call_args[0][0]
        assert entry.event_type == "created"
        assert entry.rule_id == "r1"

    def test_existing_rule_increments_version(self, engine, mock_db, mock_audit):
        mock_db.execute_read.return_value = [{"version": 2, "rule_id": "r1"}]
        engine.store_rule("r1", _YAML)
        sql, params = mock_db.execute_write.call_args[0]
        assert "UPDATE rules" in sql
        assert 3 in params  # new version = 3

    def test_existing_rule_logs_updated(self, engine, mock_db, mock_audit):
        mock_db.execute_read.return_value = [{"version": 1, "rule_id": "r1"}]
        engine.store_rule("r1", _YAML)
        entry = mock_audit.log_rule_event.call_args[0][0]
        assert entry.event_type == "updated"

    def test_sha256_in_audit_detail(self, engine, mock_db, mock_audit):
        mock_db.execute_read.return_value = []
        engine.store_rule("r1", _YAML)
        entry = mock_audit.log_rule_event.call_args[0][0]
        assert "sha256=" in entry.detail


# ---------------------------------------------------------------------------
# confirm_rule
# ---------------------------------------------------------------------------

class TestConfirmRule:
    def test_none_rule_id_raises(self, engine):
        with pytest.raises(TypeError):
            engine.confirm_rule(None)

    def test_not_found_raises(self, engine, mock_db):
        mock_db.execute_read.return_value = []
        with pytest.raises(RuleNotFoundError):
            engine.confirm_rule("missing")

    def test_sets_confirmed(self, engine, mock_db, mock_audit):
        mock_db.execute_read.return_value = [{"rule_id": "r1", "version": 1}]
        engine.confirm_rule("r1", session_id="sess-1")
        sql, params = mock_db.execute_write.call_args[0]
        assert "analyst_confirmed = 1" in sql

    def test_logs_confirmed_event(self, engine, mock_db, mock_audit):
        mock_db.execute_read.return_value = [{"rule_id": "r1", "version": 1}]
        engine.confirm_rule("r1", session_id="sess-abc")
        entry = mock_audit.log_rule_event.call_args[0][0]
        assert entry.event_type == "confirmed"
        assert entry.session_id == "sess-abc"


# ---------------------------------------------------------------------------
# export_rule
# ---------------------------------------------------------------------------

class TestExportRule:
    def test_none_rule_id_raises(self, engine):
        with pytest.raises(TypeError):
            engine.export_rule(None)

    def test_not_found_raises(self, engine, mock_db):
        mock_db.execute_read.return_value = []
        with pytest.raises(RuleNotFoundError):
            engine.export_rule("missing")

    def test_unconfirmed_raises(self, engine, mock_db):
        mock_db.execute_read.return_value = [
            {"rule_id": "r1", "analyst_confirmed": 0, "yaml_content": _YAML}
        ]
        with pytest.raises(RuleNotConfirmedError):
            engine.export_rule("r1")

    def test_confirmed_returns_yaml(self, engine, mock_db, mock_audit):
        mock_db.execute_read.return_value = [
            {"rule_id": "r1", "analyst_confirmed": 1, "yaml_content": _YAML}
        ]
        result = engine.export_rule("r1")
        assert result == _YAML

    def test_logs_exported_event(self, engine, mock_db, mock_audit):
        mock_db.execute_read.return_value = [
            {"rule_id": "r1", "analyst_confirmed": 1, "yaml_content": _YAML}
        ]
        engine.export_rule("r1", format="sigma")
        entry = mock_audit.log_rule_event.call_args[0][0]
        assert entry.event_type == "exported"
        assert "format=sigma" in entry.detail

    def test_updates_exported_at(self, engine, mock_db):
        mock_db.execute_read.return_value = [
            {"rule_id": "r1", "analyst_confirmed": 1, "yaml_content": _YAML}
        ]
        engine.export_rule("r1")
        sql, _ = mock_db.execute_write.call_args[0]
        assert "exported_at" in sql


# ---------------------------------------------------------------------------
# backtest_rule
# ---------------------------------------------------------------------------

class TestBacktestRule:
    def test_none_rule_id_raises(self, engine_with_duckdb):
        with pytest.raises(TypeError):
            engine_with_duckdb.backtest_rule(None, "sess")

    def test_none_session_id_raises(self, engine_with_duckdb):
        with pytest.raises(TypeError):
            engine_with_duckdb.backtest_rule("r1", None)

    def test_no_duckdb_raises_runtime(self, engine, mock_db):
        mock_db.execute_read.return_value = [{"rule_id": "r1", "version": 1, "yaml_content": _YAML}]
        with pytest.raises(RuntimeError):
            engine.backtest_rule("r1", "sess")

    def test_not_found_raises(self, engine_with_duckdb, mock_db):
        mock_db.execute_read.return_value = []
        with pytest.raises(RuleNotFoundError):
            engine_with_duckdb.backtest_rule("missing", "sess")

    def test_returns_backtest_result(self, engine_with_duckdb, mock_db):
        mock_db.execute_read.return_value = [
            {"rule_id": "r1", "version": 1, "yaml_content": _YAML}
        ]
        result = engine_with_duckdb.backtest_rule("r1", "sess-1")
        assert isinstance(result, BacktestResult)
        assert result.rule_id == "r1"
        assert result.session_id == "sess-1"

    def test_calls_duckdb_with_include_replay_true(
        self, engine_with_duckdb, mock_db, mock_duckdb
    ):
        mock_db.execute_read.return_value = [
            {"rule_id": "r1", "version": 1, "yaml_content": _YAML}
        ]
        engine_with_duckdb.backtest_rule("r1", "sess-1")
        mock_duckdb.execute_query.assert_called()
        call_kwargs = mock_duckdb.execute_query.call_args
        assert call_kwargs[1].get("include_replay") is True

    def test_partition_exception_skipped(self, engine_with_duckdb, mock_db, mock_duckdb):
        mock_db.execute_read.return_value = [
            {"rule_id": "r1", "version": 1, "yaml_content": _YAML}
        ]
        mock_duckdb.execute_query.side_effect = Exception("partition gone")
        result = engine_with_duckdb.backtest_rule("r1", "sess-1")
        assert result.match_count == 0

    def test_logs_backtested_event(self, engine_with_duckdb, mock_db, mock_audit):
        mock_db.execute_read.return_value = [
            {"rule_id": "r1", "version": 1, "yaml_content": _YAML}
        ]
        engine_with_duckdb.backtest_rule("r1", "sess-1")
        entry = mock_audit.log_rule_event.call_args[0][0]
        assert entry.event_type == "backtested"


# ---------------------------------------------------------------------------
# get_rule
# ---------------------------------------------------------------------------

class TestGetRule:
    def test_none_raises(self, engine):
        with pytest.raises(TypeError):
            engine.get_rule(None)

    def test_not_found_raises(self, engine, mock_db):
        mock_db.execute_read.return_value = []
        with pytest.raises(RuleNotFoundError):
            engine.get_rule("missing")

    def test_returns_dict(self, engine, mock_db):
        mock_db.execute_read.return_value = [{"rule_id": "r1", "version": 1}]
        result = engine.get_rule("r1")
        assert isinstance(result, dict)
        assert result["rule_id"] == "r1"


# ---------------------------------------------------------------------------
# list_rules
# ---------------------------------------------------------------------------

class TestListRules:
    def test_all_rules_query(self, engine, mock_db):
        mock_db.execute_read.return_value = []
        engine.list_rules()
        sql, _ = mock_db.execute_read.call_args[0]
        assert "SELECT * FROM rules" in sql
        assert "analyst_confirmed" not in sql

    def test_confirmed_only_query(self, engine, mock_db):
        mock_db.execute_read.return_value = []
        engine.list_rules(confirmed_only=True)
        sql, _ = mock_db.execute_read.call_args[0]
        assert "analyst_confirmed = 1" in sql

    def test_returns_list_of_dicts(self, engine, mock_db):
        mock_db.execute_read.return_value = [
            {"rule_id": "r1", "version": 1},
            {"rule_id": "r2", "version": 1},
        ]
        result = engine.list_rules()
        assert len(result) == 2
        assert all(isinstance(r, dict) for r in result)


# ---------------------------------------------------------------------------
# _sha256 helper
# ---------------------------------------------------------------------------

def test_sha256_deterministic():
    h1 = _sha256("content")
    h2 = _sha256("content")
    assert h1 == h2
    assert len(h1) == 64


def test_sha256_different_content():
    assert _sha256("a") != _sha256("b")


# ---------------------------------------------------------------------------
# _event_matches_rule
# ---------------------------------------------------------------------------

class TestEventMatchesRule:
    def test_match_found(self):
        row = {"message": "malware detected on host"}
        assert _event_matches_rule(row, _YAML) is True

    def test_no_match(self):
        row = {"message": "normal login event"}
        assert _event_matches_rule(row, _YAML) is False

    def test_no_keywords_section(self):
        yaml = "title: No Keywords\ndetection:\n  condition: selection\n"
        row = {"message": "anything"}
        assert _event_matches_rule(row, yaml) is False

    def test_exception_returns_false(self):
        # Pass a non-dict to simulate unexpected error
        result = _event_matches_rule(None, _YAML)
        assert result is False

    def test_none_values_skipped(self):
        row = {"message": None, "host": "malware"}
        assert _event_matches_rule(row, _YAML) is True