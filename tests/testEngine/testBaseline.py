"""
tests/testEngine/testBaseline.py
Tests for loghunter.engine.baseline.BaselineEngine
Target: 100% branch coverage
"""
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, call

from loghunter.engine.baseline import BaselineEngine, _MIN_OBSERVATIONS, _now_utc
from loghunter.exceptions import UnsupportedClassError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(time=None):
    """Return a minimal mock OCSFEvent."""
    e = MagicMock()
    e.get_time.return_value = time or datetime(2026, 1, 1, tzinfo=timezone.utc)
    return e


def _make_events(n, base_hour=0):
    """Return n mock events with incrementally different times."""
    return [
        _make_event(datetime(2026, 1, 1, base_hour + (i % 24), i % 60, 0, tzinfo=timezone.utc))
        for i in range(n)
    ]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_db():
    m = MagicMock()
    m.execute_read.return_value = []
    return m


@pytest.fixture
def mock_metrics():
    m = MagicMock()
    metric_def = MagicMock()
    m.get_metric.return_value = metric_def
    m.compute_current_value.return_value = 1.0
    return m


@pytest.fixture
def mock_audit():
    return MagicMock()


@pytest.fixture
def engine(mock_db, mock_metrics, mock_audit):
    return BaselineEngine(mock_db, mock_metrics, mock_audit)


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------

class TestInit:
    def test_none_sqlite_raises(self, mock_metrics, mock_audit):
        with pytest.raises(TypeError):
            BaselineEngine(None, mock_metrics, mock_audit)

    def test_none_metric_registry_raises(self, mock_db, mock_audit):
        with pytest.raises(TypeError):
            BaselineEngine(mock_db, None, mock_audit)

    def test_none_audit_raises(self, mock_db, mock_metrics):
        with pytest.raises(TypeError):
            BaselineEngine(mock_db, mock_metrics, None)

    def test_valid_construction(self, mock_db, mock_metrics, mock_audit):
        be = BaselineEngine(mock_db, mock_metrics, mock_audit)
        assert be is not None


# ---------------------------------------------------------------------------
# compute_baseline — TypeError / ValueError guards
# ---------------------------------------------------------------------------

class TestComputeBaselineGuards:
    def test_none_entity_type_raises(self, engine):
        with pytest.raises(TypeError):
            engine.compute_baseline(None, "alice", "login_attempt_count", 6003, [])

    def test_none_entity_value_raises(self, engine):
        with pytest.raises(TypeError):
            engine.compute_baseline("user", None, "login_attempt_count", 6003, [])

    def test_none_metric_name_raises(self, engine):
        with pytest.raises(TypeError):
            engine.compute_baseline("user", "alice", None, 6003, [])

    def test_none_class_uid_raises(self, engine):
        with pytest.raises(TypeError):
            engine.compute_baseline("user", "alice", "login_attempt_count", None, [])

    def test_none_events_raises(self, engine):
        with pytest.raises(TypeError):
            engine.compute_baseline("user", "alice", "login_attempt_count", 6003, None)

    def test_empty_entity_type_raises(self, engine):
        with pytest.raises(ValueError):
            engine.compute_baseline("  ", "alice", "login_attempt_count", 6003, [])

    def test_empty_entity_value_raises(self, engine):
        with pytest.raises(ValueError):
            engine.compute_baseline("user", "   ", "login_attempt_count", 6003, [])

    def test_empty_metric_name_raises(self, engine):
        with pytest.raises(ValueError):
            engine.compute_baseline("user", "alice", "  ", 6003, [])

    def test_metric_not_registered_raises(self, engine, mock_metrics):
        mock_metrics.get_metric.return_value = None
        with pytest.raises(ValueError):
            engine.compute_baseline("user", "alice", "bad_metric", 6003, _make_events(30))


# ---------------------------------------------------------------------------
# compute_baseline — D-004 minimum observation guard
# ---------------------------------------------------------------------------

class TestComputeBaselineMinObs:
    def test_fewer_than_30_events_no_write(self, engine, mock_db, mock_metrics):
        mock_metrics.compute_current_value.return_value = 1.0
        events = _make_events(29)
        engine.compute_baseline("user", "alice", "login_attempt_count", 6003, events)
        mock_db.execute_write.assert_not_called()

    def test_exactly_0_events_no_write(self, engine, mock_db):
        engine.compute_baseline("user", "alice", "login_attempt_count", 6003, [])
        mock_db.execute_write.assert_not_called()

    def test_30_events_triggers_write(self, engine, mock_db, mock_metrics):
        mock_metrics.compute_current_value.return_value = 1.0
        events = _make_events(30)
        engine.compute_baseline("user", "alice", "login_attempt_count", 6003, events)
        mock_db.execute_write.assert_called_once()

    def test_fewer_metric_values_than_events_may_skip(self, engine, mock_db, mock_metrics):
        """If most metric values are None, effective count drops below 30."""
        # Only 10 of 30 events produce values
        call_count = [0]
        def side(name, uid, evts):
            call_count[0] += 1
            return 1.0 if call_count[0] <= 10 else None
        mock_metrics.compute_current_value.side_effect = side
        events = _make_events(30)
        engine.compute_baseline("user", "alice", "login_attempt_count", 6003, events)
        mock_db.execute_write.assert_not_called()


# ---------------------------------------------------------------------------
# compute_baseline — successful write
# ---------------------------------------------------------------------------

class TestComputeBaselineWrite:
    def test_upsert_sql_called(self, engine, mock_db, mock_metrics):
        mock_metrics.compute_current_value.return_value = 5.0
        events = _make_events(30)
        engine.compute_baseline("user", "alice", "login_attempt_count", 6003, events)
        sql, params = mock_db.execute_write.call_args[0]
        assert "INSERT INTO baselines" in sql
        assert "ON CONFLICT" in sql
        assert params[0] == "user"
        assert params[1] == "alice"
        assert params[2] == "login_attempt_count"
        assert params[3] == 6003

    def test_mean_and_stddev_are_floats(self, engine, mock_db, mock_metrics):
        mock_metrics.compute_current_value.return_value = 3.0
        events = _make_events(30)
        engine.compute_baseline("user", "alice", "login_attempt_count", 6003, events)
        _, params = mock_db.execute_write.call_args[0]
        mean = params[4]
        stddev = params[5]
        assert isinstance(mean, float)
        assert isinstance(stddev, float)

    def test_observation_count_in_params(self, engine, mock_db, mock_metrics):
        mock_metrics.compute_current_value.return_value = 2.0
        events = _make_events(35)
        engine.compute_baseline("user", "alice", "login_attempt_count", 6003, events)
        _, params = mock_db.execute_write.call_args[0]
        obs_count = params[6]
        assert obs_count == 35


# ---------------------------------------------------------------------------
# get_baseline
# ---------------------------------------------------------------------------

class TestGetBaseline:
    def test_none_entity_type_raises(self, engine):
        with pytest.raises(TypeError):
            engine.get_baseline(None, "alice", "login_attempt_count", 6003)

    def test_none_entity_value_raises(self, engine):
        with pytest.raises(TypeError):
            engine.get_baseline("user", None, "login_attempt_count", 6003)

    def test_none_metric_raises(self, engine):
        with pytest.raises(TypeError):
            engine.get_baseline("user", "alice", None, 6003)

    def test_none_class_uid_raises(self, engine):
        with pytest.raises(TypeError):
            engine.get_baseline("user", "alice", "login_attempt_count", None)

    def test_not_found_returns_none(self, engine, mock_db):
        mock_db.execute_read.return_value = []
        result = engine.get_baseline("user", "alice", "login_attempt_count", 6003)
        assert result is None

    def test_found_returns_dict(self, engine, mock_db):
        fake_row = {
            "entity_type": "user", "entity_value": "alice",
            "metric_name": "login_attempt_count", "class_uid": 6003,
            "mean": 5.0, "stddev": 1.0, "observation_count": 30,
            "window_start": "2026-01-01T00:00:00Z",
            "window_end": "2026-01-02T00:00:00Z",
            "computed_at": "2026-01-02T00:00:00Z",
        }
        mock_db.execute_read.return_value = [fake_row]
        result = engine.get_baseline("user", "alice", "login_attempt_count", 6003)
        assert result is not None
        assert result["mean"] == 5.0

    def test_read_query_uses_params(self, engine, mock_db):
        mock_db.execute_read.return_value = []
        engine.get_baseline("user", "alice", "login_attempt_count", 6003)
        sql, params = mock_db.execute_read.call_args[0]
        assert "SELECT" in sql
        assert params == ("user", "alice", "login_attempt_count", 6003)


# ---------------------------------------------------------------------------
# _now_utc
# ---------------------------------------------------------------------------

def test_now_utc_format():
    result = _now_utc()
    assert result.endswith("Z")
    assert "T" in result