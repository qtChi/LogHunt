"""
tests/testEngine/testReplayEngine.py
Tests for loghunter.engine.replay_engine.ReplayEngine
Target: 100% branch coverage
"""
import pytest
from unittest.mock import MagicMock

from loghunter.engine.replay import ReplayEngine
from loghunter.engine.sigma_engine import BacktestResult
from loghunter.exceptions import RuleNotFoundError, ReplaySessionNotFoundError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_writer():
    m = MagicMock()
    m.write_replay_batch.return_value = 5
    return m


@pytest.fixture
def mock_sigma():
    m = MagicMock()
    m.backtest_rule.return_value = BacktestResult(
        rule_id="r1",
        session_id="sess-1",
        match_count=2,
        total_events=10,
    )
    return m


@pytest.fixture
def mock_duckdb():
    return MagicMock()


@pytest.fixture
def engine(mock_writer, mock_sigma, mock_duckdb):
    return ReplayEngine(mock_writer, mock_sigma, mock_duckdb)


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------

class TestInit:
    def test_none_writer_raises(self, mock_sigma, mock_duckdb):
        with pytest.raises(TypeError):
            ReplayEngine(None, mock_sigma, mock_duckdb)

    def test_none_sigma_raises(self, mock_writer, mock_duckdb):
        with pytest.raises(TypeError):
            ReplayEngine(mock_writer, None, mock_duckdb)

    def test_none_duckdb_raises(self, mock_writer, mock_sigma):
        with pytest.raises(TypeError):
            ReplayEngine(mock_writer, mock_sigma, None)

    def test_valid_construction(self, mock_writer, mock_sigma, mock_duckdb):
        engine = ReplayEngine(mock_writer, mock_sigma, mock_duckdb)
        assert engine is not None


# ---------------------------------------------------------------------------
# create_session
# ---------------------------------------------------------------------------

class TestCreateSession:
    def test_none_name_raises(self, engine):
        with pytest.raises(TypeError):
            engine.create_session(None)

    def test_empty_name_raises(self, engine):
        with pytest.raises(ValueError):
            engine.create_session("   ")

    def test_returns_uuid_string(self, engine):
        sid = engine.create_session("test session")
        assert isinstance(sid, str)
        assert len(sid) == 36  # UUID4 format
        # Check UUID4 structure
        parts = sid.split("-")
        assert len(parts) == 5

    def test_different_calls_return_unique_ids(self, engine):
        s1 = engine.create_session("session 1")
        s2 = engine.create_session("session 2")
        assert s1 != s2

    def test_does_not_write_to_disk(self, engine, mock_writer):
        engine.create_session("my session")
        mock_writer.write_replay_batch.assert_not_called()


# ---------------------------------------------------------------------------
# ingest_to_session
# ---------------------------------------------------------------------------

class TestIngestToSession:
    def test_none_events_raises(self, engine):
        with pytest.raises(TypeError):
            engine.ingest_to_session(None, "sess-1")

    def test_none_session_id_raises(self, engine):
        with pytest.raises(TypeError):
            engine.ingest_to_session([], None)

    def test_empty_session_id_raises(self, engine):
        with pytest.raises(ValueError):
            engine.ingest_to_session([], "  ")

    def test_delegates_to_parquet_writer(self, engine, mock_writer):
        mock_events = [MagicMock(), MagicMock()]
        count = engine.ingest_to_session(mock_events, "sess-1")
        mock_writer.write_replay_batch.assert_called_once_with(
            events=mock_events,
            session_id="sess-1",
            source_format="replay",
        )
        assert count == 5

    def test_custom_source_format_passed(self, engine, mock_writer):
        engine.ingest_to_session([], "sess-1", source_format="custom")
        call_kwargs = mock_writer.write_replay_batch.call_args[1]
        assert call_kwargs["source_format"] == "custom"

    def test_empty_events_list_returns_zero(self, engine, mock_writer):
        mock_writer.write_replay_batch.return_value = 0
        count = engine.ingest_to_session([], "sess-1")
        assert count == 0

    def test_replay_not_found_propagates(self, engine, mock_writer):
        mock_writer.write_replay_batch.side_effect = ReplaySessionNotFoundError("oops")
        with pytest.raises(ReplaySessionNotFoundError):
            engine.ingest_to_session([], "sess-bad")


# ---------------------------------------------------------------------------
# test_rule_against_session
# ---------------------------------------------------------------------------

class TestTestRuleAgainstSession:
    def test_none_rule_id_raises(self, engine):
        with pytest.raises(TypeError):
            engine.test_rule_against_session(None, "sess-1")

    def test_none_session_id_raises(self, engine):
        with pytest.raises(TypeError):
            engine.test_rule_against_session("r1", None)

    def test_delegates_to_sigma_backtest(self, engine, mock_sigma):
        result = engine.test_rule_against_session("r1", "sess-1")
        mock_sigma.backtest_rule.assert_called_once_with("r1", "sess-1")

    def test_returns_backtest_result(self, engine):
        result = engine.test_rule_against_session("r1", "sess-1")
        assert isinstance(result, BacktestResult)
        assert result.rule_id == "r1"
        assert result.match_count == 2
        assert result.total_events == 10

    def test_rule_not_found_propagates(self, engine, mock_sigma):
        mock_sigma.backtest_rule.side_effect = RuleNotFoundError("not found")
        with pytest.raises(RuleNotFoundError):
            engine.test_rule_against_session("missing", "sess-1")

    def test_include_replay_true_via_sigma(self, engine, mock_sigma):
        """
        ReplayEngine.test_rule_against_session is the ONLY entry point for
        include_replay=True (spec §11.8).  Verify it reaches SigmaEngine.
        """
        engine.test_rule_against_session("r1", "sess-1")
        # The actual include_replay=True call happens inside SigmaEngine.backtest_rule,
        # which we've already verified in testSigmaEngine.py.
        # Here we just verify delegation occurs.
        mock_sigma.backtest_rule.assert_called_once_with("r1", "sess-1")