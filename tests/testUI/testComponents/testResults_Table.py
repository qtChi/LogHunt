# tests/testUI/testResultsTable.py — 100% branch coverage for results_table.py
import sys
from unittest.mock import MagicMock
sys.modules["streamlit"] = MagicMock()

import pytest
from loghunter.ui.components.results_table import (
    select_display_columns, paginate_events, DEFAULT_COLUMNS
)

def _events(n=5, keys=None):
    keys = keys or ["time","class_uid","severity_id","actor.user.name","src_endpoint.ip","dst_endpoint.ip","activity_id","metadata.log_source"]
    return [{k: f"v{i}" for k in keys} for i in range(n)]


class TestSelectDisplayColumns:
    def test_returns_preferred_intersection(self):
        evts = _events(2)
        result = select_display_columns(evts, ["time","class_uid","nonexistent"])
        assert "time" in result and "class_uid" in result
        assert "nonexistent" not in result

    def test_falls_back_to_first_8_when_no_intersection(self):
        evts = [{"custom_a": 1, "custom_b": 2, "c":3,"d":4,"e":5,"f":6,"g":7,"h":8,"i":9}]
        result = select_display_columns(evts, ["time"])
        assert len(result) <= 8

    def test_empty_events_returns_preferred(self):
        result = select_display_columns([], DEFAULT_COLUMNS)
        assert result == DEFAULT_COLUMNS

    def test_all_preferred_present(self):
        evts = _events(1)
        result = select_display_columns(evts, DEFAULT_COLUMNS)
        assert len(result) > 0


class TestPaginateEvents:
    def test_page_size_zero_raises(self):
        with pytest.raises(ValueError, match="page_size must be >= 1"):
            paginate_events([], 0, 0)

    def test_page_size_negative_raises(self):
        with pytest.raises(ValueError):
            paginate_events([], 0, -1)

    def test_empty_events_returns_empty_one_page(self):
        events, total = paginate_events([], 0, 10)
        assert events == [] and total == 1

    def test_single_page(self):
        evts = _events(3)
        events, total = paginate_events(evts, 0, 10)
        assert len(events) == 3 and total == 1

    def test_multiple_pages(self):
        evts = _events(25)
        _, total = paginate_events(evts, 0, 10)
        assert total == 3

    def test_correct_slice_returned(self):
        evts = list(range(20))
        page_events, _ = paginate_events(evts, 1, 5)
        assert page_events == [5,6,7,8,9]

    def test_out_of_range_page_clamped_to_last(self):
        evts = _events(5)
        events, total = paginate_events(evts, 99, 2)
        assert len(events) > 0

    def test_negative_page_clamped_to_zero(self):
        evts = _events(5)
        events, total = paginate_events(evts, -1, 3)
        assert events == evts[:3]

    def test_exact_page_boundary(self):
        evts = list(range(10))
        events, total = paginate_events(evts, 1, 5)
        assert events == [5,6,7,8,9] and total == 2

    def test_page_size_one(self):
        evts = _events(3)
        _, total = paginate_events(evts, 0, 1)
        assert total == 3