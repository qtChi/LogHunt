# tests/testUI/testSettings.py — 100% branch coverage for ui/tabs/settings.py pure functions
import sys
from unittest.mock import MagicMock
sys.modules["streamlit"] = MagicMock()
sys.modules["loghunter.ui.components.results_table"] = MagicMock()
sys.modules["loghunter.ui.components"] = MagicMock()

from loghunter.ui.tabs.settings import (
    create_and_ingest_session, run_backtest, format_backtest_result
)


def _backtest_result(match_count=3, total_events=100):
    r = MagicMock()
    r.rule_id = "rule1"
    r.session_id = "sess-abc"
    r.match_count = match_count
    r.total_events = total_events
    r.matched_events = [{"k": "v"}] * match_count
    r.executed_at = "2026-01-01T00:00:00Z"
    return r


class TestCreateAndIngestSession:
    def test_creates_session_with_name(self):
        replay = MagicMock()
        replay.create_session.return_value = "sess-123"
        replay.ingest_to_session.return_value = 5
        result = create_and_ingest_session("my-session", [MagicMock()]*5, replay)
        assert result["session_id"] == "sess-123"
        assert result["event_count"] == 5
        assert result["error"] is None

    def test_empty_events_skips_ingest(self):
        replay = MagicMock()
        replay.create_session.return_value = "sess-123"
        result = create_and_ingest_session("my-session", [], replay)
        replay.ingest_to_session.assert_not_called()
        assert result["event_count"] == 0

    def test_exception_returns_error(self):
        replay = MagicMock()
        replay.create_session.side_effect = RuntimeError("DB error")
        result = create_and_ingest_session("sess", [], replay)
        assert result["error"] == "DB error"
        assert result["session_id"] is None


class TestRunBacktest:
    def test_happy_path(self):
        replay = MagicMock()
        replay.test_rule_against_session.return_value = _backtest_result()
        result = run_backtest("rule1", "sess-1", replay)
        assert result["result"] is not None and result["error"] is None

    def test_exception_returns_error(self):
        replay = MagicMock()
        replay.test_rule_against_session.side_effect = ValueError("not found")
        result = run_backtest("bad_rule", "sess-1", replay)
        assert result["error"] == "not found" and result["result"] is None


class TestFormatBacktestResult:
    def test_returns_required_keys(self):
        d = format_backtest_result(_backtest_result())
        for key in ("rule_id","session_id","match_count","total_events","match_rate","executed_at"):
            assert key in d

    def test_match_rate_calculated(self):
        d = format_backtest_result(_backtest_result(match_count=5, total_events=100))
        assert d["match_rate"] == "5.0%"

    def test_zero_total_events_shows_na(self):
        d = format_backtest_result(_backtest_result(match_count=0, total_events=0))
        assert d["match_rate"] == "N/A"

    def test_broken_result_returns_empty_dict(self):
        bad = MagicMock()
        type(bad).rule_id = property(lambda self: (_ for _ in ()).throw(RuntimeError()))
        assert format_backtest_result(bad) == {}