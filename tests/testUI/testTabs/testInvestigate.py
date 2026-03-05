# tests/testUI/testInvestigate.py — 100% branch coverage for investigate.py pure functions
import sys
from unittest.mock import MagicMock
sys.modules["streamlit"] = MagicMock()
sys.modules["loghunter.ui.components.results_table"] = MagicMock()
sys.modules["loghunter.ui.components.timeline_chart"] = MagicMock()
sys.modules["loghunter.ui.components"] = MagicMock()

from loghunter.ui.tabs.investigate import execute_nl_query, execute_manual_query, format_events_for_display


def _intent(valid=True, confidence=0.9):
    intent = MagicMock()
    intent.is_valid.return_value = valid
    intent.confidence = confidence
    intent.to_builder_args.return_value = {"class_uid": 6003, "filters": {}, "time_range": None}
    return intent

def _event(d=None):
    e = MagicMock()
    e.to_dict.return_value = d or {"time": "2026-01-01", "class_uid": 6003}
    return e


class TestExecuteNlQuery:
    def test_valid_intent_executes_query(self):
        extractor = MagicMock()
        extractor.extract.return_value = _intent(valid=True)
        builder = MagicMock()
        builder.execute.return_value = [_event(), _event()]
        result = execute_nl_query("failed logins", extractor, builder)
        assert result["row_count"] == 2
        assert result["error"] is None

    def test_invalid_intent_returns_error(self):
        extractor = MagicMock()
        extractor.extract.return_value = _intent(valid=False)
        result = execute_nl_query("something vague", extractor, MagicMock())
        assert result["error"] is not None
        assert result["row_count"] == 0

    def test_extractor_exception_returns_error(self):
        extractor = MagicMock()
        extractor.extract.side_effect = RuntimeError("LLM down")
        result = execute_nl_query("test", extractor, MagicMock())
        assert result["error"] == "LLM down"
        assert result["events"] == []

    def test_builder_exception_returns_error(self):
        extractor = MagicMock()
        extractor.extract.return_value = _intent(valid=True)
        builder = MagicMock()
        builder.execute.side_effect = RuntimeError("DB error")
        result = execute_nl_query("test", extractor, builder)
        assert "DB error" in result["error"]

    def test_natural_language_preserved_in_result(self):
        extractor = MagicMock()
        intent = _intent(valid=True)
        extractor.extract.return_value = intent
        builder = MagicMock()
        builder.execute.return_value = []
        result = execute_nl_query("show me logins", extractor, builder)
        assert result["intent"] is intent


class TestExecuteManualQuery:
    def test_happy_path(self):
        builder = MagicMock()
        builder.execute.return_value = [_event()]
        result = execute_manual_query(6003, {}, 24, builder)
        assert result["row_count"] == 1 and result["error"] is None

    def test_none_time_range_hours(self):
        builder = MagicMock()
        builder.execute.return_value = []
        result = execute_manual_query(6003, {}, None, builder)
        assert result["error"] is None
        # time_range should be None when hours is None/0/falsy
        call_args = builder.execute.call_args
        assert call_args[0][2] is None

    def test_builder_exception_returns_error(self):
        builder = MagicMock()
        builder.execute.side_effect = RuntimeError("partition missing")
        result = execute_manual_query(6003, {}, 24, builder)
        assert "partition missing" in result["error"]

    def test_empty_result(self):
        builder = MagicMock()
        builder.execute.return_value = []
        result = execute_manual_query(3001, {}, 1, builder)
        assert result["row_count"] == 0 and result["events"] == []


class TestFormatEventsForDisplay:
    def test_empty_list_returns_empty(self):
        assert format_events_for_display([]) == []

    def test_none_returns_empty(self):
        assert format_events_for_display(None) == []

    def test_converts_events_to_dicts(self):
        events = [_event({"time": "t1"}), _event({"time": "t2"})]
        result = format_events_for_display(events)
        assert result == [{"time": "t1"}, {"time": "t2"}]

    def test_broken_event_skipped(self):
        bad = MagicMock()
        bad.to_dict.side_effect = RuntimeError("broken")
        good = _event({"time": "t1"})
        result = format_events_for_display([bad, good])
        assert result == [{"time": "t1"}]