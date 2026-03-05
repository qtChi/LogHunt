# tests/testUI/testTimelineChart.py — 100% branch coverage for timeline_chart.py
import sys
from unittest.mock import MagicMock
sys.modules["streamlit"] = MagicMock()

from datetime import datetime, timezone
import pytest

from loghunter.ui.components.timeline_chart import build_timeline_data, _floor_to_bucket


class TestFloorToBucket:
    def test_floors_to_hour_boundary(self):
        dt = datetime(2026, 1, 1, 14, 35, 22)
        result = _floor_to_bucket(dt, 60)
        assert result.hour == 14 and result.minute == 0 and result.second == 0

    def test_floors_to_30min_boundary(self):
        dt = datetime(2026, 1, 1, 14, 45, 0)
        result = _floor_to_bucket(dt, 30)
        assert result.minute == 30

    def test_already_on_boundary_unchanged(self):
        dt = datetime(2026, 1, 1, 12, 0, 0)
        result = _floor_to_bucket(dt, 60)
        assert result.hour == 12 and result.minute == 0


class TestBuildTimelineData:
    def _evt(self, hour=10, minute=0):
        return {"time": datetime(2026, 1, 1, hour, minute, 0)}

    def test_bucket_minutes_zero_raises(self):
        with pytest.raises(ValueError, match="bucket_minutes must be >= 1"):
            build_timeline_data([], 0)

    def test_bucket_minutes_negative_raises(self):
        with pytest.raises(ValueError):
            build_timeline_data([], -5)

    def test_empty_events_returns_empty_df(self):
        df = build_timeline_data([])
        assert len(df) == 0

    def test_single_event_produces_one_row(self):
        df = build_timeline_data([self._evt()])
        assert len(df) == 1 and "timestamp" in df.columns and "count" in df.columns

    def test_events_in_same_bucket_counted_together(self):
        events = [self._evt(10, 5), self._evt(10, 10), self._evt(10, 55)]
        df = build_timeline_data(events, bucket_minutes=60)
        assert df["count"].iloc[0] == 3

    def test_events_in_different_buckets_separate_rows(self):
        events = [self._evt(10, 0), self._evt(11, 0)]
        df = build_timeline_data(events, bucket_minutes=60)
        assert len(df) == 2

    def test_no_time_field_skipped(self):
        events = [{"class_uid": 6003}, self._evt(10)]
        df = build_timeline_data(events)
        assert len(df) == 1

    def test_bad_time_value_skipped(self):
        events = [{"time": "not-a-date"}, self._evt(10)]
        df = build_timeline_data(events)
        assert len(df) == 1

    def test_none_time_skipped(self):
        events = [{"time": None}, self._evt(10)]
        df = build_timeline_data(events)
        assert len(df) == 1

    def test_all_bad_times_returns_empty(self):
        events = [{"time": None}, {"time": "bad"}]
        df = build_timeline_data(events)
        assert len(df) == 0

    def test_sorted_by_time_ascending(self):
        events = [self._evt(12), self._evt(10), self._evt(11)]
        df = build_timeline_data(events, bucket_minutes=60)
        assert list(df["timestamp"]) == sorted(df["timestamp"].tolist())

    def test_string_iso_time_parsed(self):
        events = [{"time": "2026-01-01T10:30:00"}]
        df = build_timeline_data(events, bucket_minutes=60)
        assert len(df) == 1