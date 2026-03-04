"""
tests/testEngine/testAnomaly.py
Tests for loghunter.engine.anomaly — AnomalyResult + AnomalyDetector
Target: 100% branch coverage
"""
import math
import pytest
from unittest.mock import MagicMock

from loghunter.engine.anomaly import AnomalyDetector, AnomalyResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_baseline():
    m = MagicMock()
    m.get_baseline.return_value = {
        "mean": 10.0,
        "stddev": 2.0,
    }
    return m


@pytest.fixture
def mock_metrics():
    return MagicMock()


@pytest.fixture
def detector(mock_baseline, mock_metrics):
    return AnomalyDetector(mock_baseline, mock_metrics)


# ---------------------------------------------------------------------------
# AnomalyResult dataclass
# ---------------------------------------------------------------------------

class TestAnomalyResult:
    def test_default_threshold(self):
        r = AnomalyResult(
            entity_type="user",
            entity_value="alice",
            metric_name="login_attempt_count",
            current_value=20.0,
            baseline_mean=10.0,
            baseline_stddev=2.0,
            z_score=5.0,
            is_anomaly=True,
        )
        assert r.threshold == 3.0

    def test_fields_accessible(self):
        r = AnomalyResult(
            entity_type="ip",
            entity_value="1.2.3.4",
            metric_name="net_connection_count_per_hour",
            current_value=100.0,
            baseline_mean=50.0,
            baseline_stddev=5.0,
            z_score=10.0,
            is_anomaly=True,
            threshold=3.0,
        )
        assert r.entity_type == "ip"
        assert r.is_anomaly is True


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------

class TestInit:
    def test_none_baseline_raises(self, mock_metrics):
        with pytest.raises(TypeError):
            AnomalyDetector(None, mock_metrics)

    def test_none_metrics_raises(self, mock_baseline):
        with pytest.raises(TypeError):
            AnomalyDetector(mock_baseline, None)

    def test_valid_construction(self, mock_baseline, mock_metrics):
        d = AnomalyDetector(mock_baseline, mock_metrics)
        assert d is not None


# ---------------------------------------------------------------------------
# detect — TypeError / ValueError guards
# ---------------------------------------------------------------------------

class TestDetectGuards:
    def test_none_entity_type_raises(self, detector):
        with pytest.raises(TypeError):
            detector.detect(None, "alice", "login_attempt_count", 6003, 15.0)

    def test_none_entity_value_raises(self, detector):
        with pytest.raises(TypeError):
            detector.detect("user", None, "login_attempt_count", 6003, 15.0)

    def test_none_metric_raises(self, detector):
        with pytest.raises(TypeError):
            detector.detect("user", "alice", None, 6003, 15.0)

    def test_none_class_uid_raises(self, detector):
        with pytest.raises(TypeError):
            detector.detect("user", "alice", "login_attempt_count", None, 15.0)

    def test_none_current_value_raises(self, detector):
        with pytest.raises(TypeError):
            detector.detect("user", "alice", "login_attempt_count", 6003, None)

    def test_bool_current_value_raises(self, detector):
        with pytest.raises(ValueError):
            detector.detect("user", "alice", "login_attempt_count", 6003, True)

    def test_nan_current_value_raises(self, detector):
        with pytest.raises(ValueError):
            detector.detect("user", "alice", "login_attempt_count", 6003, float("nan"))

    def test_inf_current_value_raises(self, detector):
        with pytest.raises(ValueError):
            detector.detect("user", "alice", "login_attempt_count", 6003, float("inf"))

    def test_neg_inf_current_value_raises(self, detector):
        with pytest.raises(ValueError):
            detector.detect("user", "alice", "login_attempt_count", 6003, float("-inf"))

    def test_string_current_value_raises(self, detector):
        with pytest.raises(ValueError):
            detector.detect("user", "alice", "login_attempt_count", 6003, "fifteen")


# ---------------------------------------------------------------------------
# detect — no baseline
# ---------------------------------------------------------------------------

class TestDetectNoBaseline:
    def test_returns_none_when_no_baseline(self, detector, mock_baseline):
        mock_baseline.get_baseline.return_value = None
        result = detector.detect("user", "alice", "login_attempt_count", 6003, 15.0)
        assert result is None


# ---------------------------------------------------------------------------
# detect — anomaly calculations
# ---------------------------------------------------------------------------

class TestDetectCalculations:
    def test_normal_z_score_not_anomaly(self, detector):
        # mean=10, stddev=2, current=11 → z=0.5
        result = detector.detect("user", "alice", "login_attempt_count", 6003, 11.0)
        assert result is not None
        assert pytest.approx(result.z_score, rel=1e-6) == 0.5
        assert result.is_anomaly is False

    def test_high_z_score_is_anomaly(self, detector):
        # mean=10, stddev=2, current=20 → z=5.0
        result = detector.detect("user", "alice", "login_attempt_count", 6003, 20.0)
        assert result is not None
        assert result.z_score == pytest.approx(5.0)
        assert result.is_anomaly is True

    def test_boundary_z_exactly_3_not_anomaly(self, detector):
        # z = 3.0 → NOT anomaly (> not >=)
        result = detector.detect("user", "alice", "login_attempt_count", 6003, 16.0)
        assert result.z_score == pytest.approx(3.0)
        assert result.is_anomaly is False

    def test_boundary_z_just_above_3_is_anomaly(self, detector):
        # mean=10, stddev=2, current=16.001 → z > 3
        result = detector.detect("user", "alice", "login_attempt_count", 6003, 16.001)
        assert result.is_anomaly is True

    def test_negative_z_score_large_magnitude_is_anomaly(self, detector):
        # mean=10, stddev=2, current=2 → z=-4
        result = detector.detect("user", "alice", "login_attempt_count", 6003, 2.0)
        assert result.z_score == pytest.approx(-4.0)
        assert result.is_anomaly is True

    def test_result_fields_populated(self, detector):
        result = detector.detect("user", "alice", "login_attempt_count", 6003, 11.0)
        assert result.entity_type == "user"
        assert result.entity_value == "alice"
        assert result.metric_name == "login_attempt_count"
        assert result.current_value == 11.0
        assert result.baseline_mean == 10.0
        assert result.baseline_stddev == 2.0
        assert result.threshold == 3.0

    def test_zero_stddev_same_value_z_zero(self, detector, mock_baseline):
        mock_baseline.get_baseline.return_value = {"mean": 10.0, "stddev": 0.0}
        result = detector.detect("user", "alice", "login_attempt_count", 6003, 10.0)
        assert result.z_score == 0.0
        assert result.is_anomaly is False

    def test_zero_stddev_different_value_is_anomaly(self, detector, mock_baseline):
        mock_baseline.get_baseline.return_value = {"mean": 10.0, "stddev": 0.0}
        result = detector.detect("user", "alice", "login_attempt_count", 6003, 15.0)
        assert result.is_anomaly is True

    def test_int_current_value_accepted(self, detector):
        result = detector.detect("user", "alice", "login_attempt_count", 6003, 11)
        assert result is not None
        assert result.current_value == 11.0