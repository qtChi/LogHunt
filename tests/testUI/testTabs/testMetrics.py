# tests/testUI/testMetrics.py — 100% branch coverage for ui/tabs/metrics.py pure functions
import sys
from unittest.mock import MagicMock
sys.modules["streamlit"] = MagicMock()

from loghunter.ui.tabs.metrics import (
    get_available_entities, compute_and_detect, format_anomaly_for_display
)


def _event(field_value=None, raises=False):
    e = MagicMock()
    if raises:
        e.get_field.side_effect = ValueError("unknown field")
    else:
        e.get_field.return_value = field_value
    return e

def _anomaly_result(is_anomaly=True, z_score=4.5):
    r = MagicMock()
    r.entity_type = "user"
    r.entity_value = "jsmith"
    r.metric_name = "auth_count"
    r.current_value = 42.0
    r.baseline_mean = 5.0
    r.z_score = z_score
    r.is_anomaly = is_anomaly
    return r


class TestGetAvailableEntities:
    def test_extracts_unique_values(self):
        events = [_event("alice"), _event("bob"), _event("alice")]
        result = get_available_entities(events, "actor.user.name")
        assert result == ["alice", "bob"]

    def test_none_values_excluded(self):
        events = [_event(None), _event("alice")]
        result = get_available_entities(events, "actor.user.name")
        assert result == ["alice"]

    def test_exception_on_event_skipped(self):
        events = [_event(raises=True), _event("bob")]
        result = get_available_entities(events, "actor.user.name")
        assert result == ["bob"]

    def test_empty_events_returns_empty(self):
        assert get_available_entities([], "actor.user.name") == []

    def test_none_events_returns_empty(self):
        assert get_available_entities(None, "actor.user.name") == []

    def test_returns_sorted(self):
        events = [_event("charlie"), _event("alice"), _event("bob")]
        result = get_available_entities(events, "field")
        assert result == sorted(result)


class TestComputeAndDetect:
    def test_happy_path_returns_result(self):
        baseline = MagicMock()
        baseline.compute_baseline.return_value = None
        baseline.get_baseline.return_value = {"mean": 5.0, "stddev": 1.0}
        detector = MagicMock()
        detector.detect.return_value = _anomaly_result()
        events = [MagicMock(), MagicMock()]
        result = compute_and_detect("user","jsmith","auth_count",6003, events, baseline, detector, MagicMock())
        assert result["error"] is None
        assert result["anomaly_result"] is not None
        assert result["current_value"] == 2.0  # len(events)

    def test_no_anomaly_result_none(self):
        baseline = MagicMock()
        baseline.get_baseline.return_value = {}
        detector = MagicMock()
        detector.detect.return_value = None
        result = compute_and_detect("user","jsmith","m",6003,[],baseline,detector,MagicMock())
        assert result["anomaly_result"] is None and result["error"] is None

    def test_exception_returns_error(self):
        baseline = MagicMock()
        baseline.compute_baseline.side_effect = RuntimeError("baseline error")
        result = compute_and_detect("user","jsmith","m",6003,[],baseline,MagicMock(),MagicMock())
        assert "baseline error" in result["error"]
        assert result["anomaly_result"] is None

    def test_none_events_treated_as_empty(self):
        baseline = MagicMock()
        baseline.get_baseline.return_value = None
        detector = MagicMock()
        detector.detect.return_value = None
        result = compute_and_detect("user","jsmith","m",6003,None,baseline,detector,MagicMock())
        assert result["current_value"] == 0.0 and result["error"] is None


class TestFormatAnomalyForDisplay:
    def test_returns_dict_with_required_keys(self):
        result = format_anomaly_for_display(_anomaly_result())
        for key in ("entity","metric","current_value","baseline_mean","z_score","is_anomaly"):
            assert key in result

    def test_entity_formatted_correctly(self):
        result = format_anomaly_for_display(_anomaly_result())
        assert result["entity"] == "user=jsmith"

    def test_broken_result_returns_empty_dict(self):
        bad = MagicMock()
        bad.entity_type = MagicMock()
        type(bad).entity_value = property(lambda self: (_ for _ in ()).throw(RuntimeError()))
        result = format_anomaly_for_display(bad)
        assert result == {}