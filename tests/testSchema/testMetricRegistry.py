# ==============================================================================
# tests/testSchema/testMetricRegistry.py
#
# Tests for loghunter/schema/metric_registry.py
#
# Coverage strategy — every branch explicitly targeted:
#
# Constructor:
#   None path → TypeError
#   Empty/whitespace path → ValueError
#   Non-existent path → FileNotFoundError
#   Invalid JSON → ValueError
#   Missing 'metrics' key → ValueError
#   'metrics' not a list → ValueError
#   Metric missing required key (each) → ValueError
#   Unsupported computation type → ValueError
#   Duplicate (name, class_uid) pair → ValueError
#   class_uid not in SUPPORTED_CLASSES → loaded but not in _by_class
#   Valid file → loads all nine built-in metrics
#
# get_metric:
#   Known (name, class_uid) → MetricDefinition
#   Unknown name → None
#   Unknown class_uid → None
#   None inputs → None (never raises)
#
# get_metrics_for_class:
#   Supported class with metrics → non-empty list
#   Supported class with no metrics → empty list
#   Unsupported class → UnsupportedClassError
#   Return is a copy
#
# compute_current_value:
#   None events → TypeError
#   Unregistered metric → ValueError
#   Empty events list → None
#   count computation → correct count
#   distinct_field_count → correct distinct count
#   distinct_field_count with None target_field → None
#   sum_field → correct sum
#   sum_field with None target_field → None
#   rate_per_hour with < 2 events → None
#   rate_per_hour with zero time span → None
#   rate_per_hour with valid span → correct rate
#   sum_field with non-numeric values → skipped
#
# MetricDefinition:
#   frozen / immutable
#   target_field None for count and rate
#
# Computation handlers (independently):
#   _compute_count
#   _compute_distinct_field_count
#   _compute_sum_field
#   _compute_rate_per_hour
# ==============================================================================

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from loghunter.exceptions import UnsupportedClassError
from loghunter.schema.metric_registry import (
    MetricDefinition,
    MetricRegistry,
    SUPPORTED_COMPUTATIONS,
    _compute_count,
    _compute_distinct_field_count,
    _compute_sum_field,
    _compute_rate_per_hour,
)
from loghunter.schema.ocsf_field_registry import SUPPORTED_CLASSES

CONFIG_DIR = Path(__file__).resolve().parent.parent.parent / "config"
METRICS_PATH = str(CONFIG_DIR / "metrics.json")

UTC = timezone.utc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_metrics(tmp_path, metrics: list[dict]) -> str:
    p = tmp_path / "metrics.json"
    p.write_text(json.dumps({"version": "1.0.0", "metrics": metrics}),
                 encoding="utf-8")
    return str(p)


def _minimal_metric(**overrides) -> dict:
    base = {
        "metric_name": "test_metric",
        "class_uid": 6003,
        "entity_type": "user",
        "entity_field": "actor.user.name",
        "computation": "count",
        "target_field": None,
        "description": "A test metric.",
    }
    base.update(overrides)
    return base


def _make_event(registry, class_uid=6003, time=None, **fields):
    """Build a minimal OCSFEvent for computation tests."""
    from loghunter.schema.ocsf_event import OCSFEvent
    event = OCSFEvent(
        class_uid=class_uid,
        activity_id=1,
        severity_id=1,
        time=time or datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC),
        metadata_log_source="test",
        metadata_original_time="2026-01-01T00:00:00Z",
        registry=registry,
    )
    for k, v in fields.items():
        event._fields[k] = v
    return event


# ==============================================================================
# TestConstructorValid
# ==============================================================================

class TestConstructorValid:

    def test_loads_real_metrics_file(self):
        registry = MetricRegistry(METRICS_PATH)
        assert registry is not None

    def test_all_nine_builtin_metrics_loaded(self):
        registry = MetricRegistry(METRICS_PATH)
        expected = {
            "auth_count_per_hour",
            "auth_distinct_src_ips",
            "process_exec_count",
            "process_distinct_names",
            "net_connection_count_per_hour",
            "net_distinct_dst_ports",
            "net_bytes_out_per_hour",
            "child_process_spawn_rate",
            "login_attempt_count",
        }
        loaded = {
            md.metric_name
            for uid in SUPPORTED_CLASSES
            for md in registry.get_metrics_for_class(uid)
        }
        assert expected.issubset(loaded)

    def test_empty_metrics_list_is_valid(self, tmp_path):
        path = _write_metrics(tmp_path, [])
        registry = MetricRegistry(path)
        assert registry is not None

    def test_metric_with_unsupported_class_uid_not_in_by_class(
        self, tmp_path
    ):
        # class_uid 9999 is not in SUPPORTED_CLASSES — metric loads but
        # is not indexed in _by_class
        m = _minimal_metric(class_uid=9999)
        path = _write_metrics(tmp_path, [m])
        registry = MetricRegistry(path)
        md = registry.get_metric("test_metric", 9999)
        assert md is not None
        # Not findable via get_metrics_for_class (would raise)
        for uid in SUPPORTED_CLASSES:
            names = [m.metric_name for m in registry.get_metrics_for_class(uid)]
            assert "test_metric" not in names

    def test_target_field_none_stored_as_none(self, tmp_path):
        m = _minimal_metric(computation="count", target_field=None)
        path = _write_metrics(tmp_path, [m])
        registry = MetricRegistry(path)
        md = registry.get_metric("test_metric", 6003)
        assert md.target_field is None

    def test_empty_string_target_field_stored_as_none(self, tmp_path):
        m = _minimal_metric(computation="count", target_field="")
        path = _write_metrics(tmp_path, [m])
        registry = MetricRegistry(path)
        md = registry.get_metric("test_metric", 6003)
        assert md.target_field is None


# ==============================================================================
# TestConstructorInvalidInputs
# ==============================================================================

class TestConstructorInvalidInputs:

    def test_none_path_raises_type_error(self):
        with pytest.raises(TypeError):
            MetricRegistry(None)

    def test_empty_string_raises_value_error(self):
        with pytest.raises(ValueError):
            MetricRegistry("")

    def test_whitespace_string_raises_value_error(self):
        with pytest.raises(ValueError):
            MetricRegistry("   ")

    def test_nonexistent_path_raises_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            MetricRegistry("/no/such/file.json")

    def test_invalid_json_raises_value_error(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not valid", encoding="utf-8")
        with pytest.raises(ValueError, match="not valid JSON"):
            MetricRegistry(str(p))

    def test_missing_metrics_key_raises_value_error(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text(json.dumps({"version": "1.0.0"}), encoding="utf-8")
        with pytest.raises(ValueError, match="'metrics'"):
            MetricRegistry(str(p))

    def test_metrics_as_dict_raises_value_error(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text(json.dumps({"metrics": {}}), encoding="utf-8")
        with pytest.raises(ValueError, match="'metrics'"):
            MetricRegistry(str(p))

    @pytest.mark.parametrize("missing_key", [
        "metric_name", "class_uid", "entity_type",
        "entity_field", "computation",
    ])
    def test_metric_missing_required_key_raises_value_error(
        self, tmp_path, missing_key
    ):
        m = _minimal_metric()
        del m[missing_key]
        path = _write_metrics(tmp_path, [m])
        with pytest.raises(ValueError):
            MetricRegistry(path)

    def test_unsupported_computation_raises_value_error(self, tmp_path):
        m = _minimal_metric(computation="average")
        path = _write_metrics(tmp_path, [m])
        with pytest.raises(ValueError, match="Unsupported computation"):
            MetricRegistry(path)

    def test_duplicate_metric_name_class_raises_value_error(self, tmp_path):
        m1 = _minimal_metric(metric_name="dup_metric", class_uid=6003)
        m2 = _minimal_metric(metric_name="dup_metric", class_uid=6003)
        path = _write_metrics(tmp_path, [m1, m2])
        with pytest.raises(ValueError, match="Duplicate"):
            MetricRegistry(path)

    def test_same_name_different_class_is_valid(self, tmp_path):
        # Same metric_name for different class_uid is allowed
        m1 = _minimal_metric(metric_name="shared_metric", class_uid=6003)
        m2 = _minimal_metric(metric_name="shared_metric", class_uid=4001)
        path = _write_metrics(tmp_path, [m1, m2])
        registry = MetricRegistry(path)
        assert registry.get_metric("shared_metric", 6003) is not None
        assert registry.get_metric("shared_metric", 4001) is not None


# ==============================================================================
# TestGetMetric
# ==============================================================================

class TestGetMetric:

    def test_known_metric_returns_definition(self):
        registry = MetricRegistry(METRICS_PATH)
        md = registry.get_metric("auth_count_per_hour", 6003)
        assert isinstance(md, MetricDefinition)
        assert md.metric_name == "auth_count_per_hour"
        assert md.class_uid == 6003

    def test_unknown_metric_name_returns_none(self):
        registry = MetricRegistry(METRICS_PATH)
        assert registry.get_metric("no_such_metric", 6003) is None

    def test_unknown_class_uid_returns_none(self):
        registry = MetricRegistry(METRICS_PATH)
        assert registry.get_metric("auth_count_per_hour", 9999) is None

    def test_both_unknown_returns_none(self):
        registry = MetricRegistry(METRICS_PATH)
        assert registry.get_metric("no_metric", 9999) is None

    def test_none_metric_name_returns_none_never_raises(self):
        registry = MetricRegistry(METRICS_PATH)
        assert registry.get_metric(None, 6003) is None

    def test_none_class_uid_returns_none_never_raises(self):
        registry = MetricRegistry(METRICS_PATH)
        assert registry.get_metric("auth_count_per_hour", None) is None

    def test_correct_metric_attributes(self):
        registry = MetricRegistry(METRICS_PATH)
        md = registry.get_metric("auth_distinct_src_ips", 6003)
        assert md.entity_type == "user"
        assert md.entity_field == "actor.user.name"
        assert md.computation == "distinct_field_count"
        assert md.target_field == "src_endpoint.ip"


# ==============================================================================
# TestGetMetricsForClass
# ==============================================================================

class TestGetMetricsForClass:

    @pytest.mark.parametrize("class_uid,expected_count", [
        (6003, 3),  # auth_count_per_hour, auth_distinct_src_ips, login_attempt_count
        (4001, 3),  # process_exec_count, process_distinct_names, child_process_spawn_rate
        (3001, 3),  # net_connection_count_per_hour, net_distinct_dst_ports, net_bytes_out_per_hour
        (1001, 0),  # no metrics defined for file activity class
        (3002, 0),  # no metrics defined for http activity class
    ])
    def test_correct_metric_count_per_class(self, class_uid, expected_count):
        registry = MetricRegistry(METRICS_PATH)
        metrics = registry.get_metrics_for_class(class_uid)
        assert len(metrics) == expected_count

    def test_returns_list_of_metric_definitions(self):
        registry = MetricRegistry(METRICS_PATH)
        metrics = registry.get_metrics_for_class(6003)
        assert all(isinstance(m, MetricDefinition) for m in metrics)

    def test_unsupported_class_raises_unsupported_class_error(self):
        registry = MetricRegistry(METRICS_PATH)
        with pytest.raises(UnsupportedClassError):
            registry.get_metrics_for_class(9999)

    def test_unsupported_class_is_also_value_error(self):
        registry = MetricRegistry(METRICS_PATH)
        with pytest.raises(ValueError):
            registry.get_metrics_for_class(0)

    def test_return_is_copy_not_internal_reference(self):
        registry = MetricRegistry(METRICS_PATH)
        metrics = registry.get_metrics_for_class(6003)
        original_len = len(metrics)
        metrics.clear()
        assert len(registry.get_metrics_for_class(6003)) == original_len

    def test_empty_class_returns_empty_list(self):
        registry = MetricRegistry(METRICS_PATH)
        assert registry.get_metrics_for_class(1001) == []


# ==============================================================================
# TestComputeCurrentValue
# ==============================================================================

class TestComputeCurrentValue:

    def test_none_events_raises_type_error(self):
        registry = MetricRegistry(METRICS_PATH)
        with pytest.raises(TypeError):
            registry.compute_current_value("auth_count_per_hour", 6003, None)

    def test_unregistered_metric_raises_value_error(self):
        registry = MetricRegistry(METRICS_PATH)
        with pytest.raises(ValueError, match="not registered"):
            registry.compute_current_value("no_such_metric", 6003, [])

    def test_empty_events_returns_none(self, ocsf_registry):
        registry = MetricRegistry(METRICS_PATH)
        result = registry.compute_current_value(
            "auth_count_per_hour", 6003, []
        )
        assert result is None

    def test_count_computation_returns_event_count(self, ocsf_registry):
        registry = MetricRegistry(METRICS_PATH)
        events = [_make_event(ocsf_registry) for _ in range(5)]
        result = registry.compute_current_value(
            "process_exec_count", 4001, events
        )
        assert result == 5.0

    def test_count_single_event(self, ocsf_registry):
        registry = MetricRegistry(METRICS_PATH)
        events = [_make_event(ocsf_registry)]
        result = registry.compute_current_value(
            "login_attempt_count", 6003, events
        )
        assert result == 1.0

    def test_distinct_field_count_returns_distinct_values(
        self, ocsf_registry
    ):
        registry = MetricRegistry(METRICS_PATH)
        e1 = _make_event(ocsf_registry, class_uid=3001,
                         **{"src_endpoint.ip": "1.1.1.1"})
        e2 = _make_event(ocsf_registry, class_uid=3001,
                         **{"src_endpoint.ip": "2.2.2.2"})
        e3 = _make_event(ocsf_registry, class_uid=3001,
                         **{"src_endpoint.ip": "1.1.1.1"})  # duplicate
        result = registry.compute_current_value(
            "net_distinct_dst_ports", 3001, [e1, e2, e3]
        )
        # target_field is dst_endpoint.port — none set, so 0 distinct
        assert result == 0.0

    def test_distinct_field_count_with_set_target_field(self, ocsf_registry):
        registry = MetricRegistry(METRICS_PATH)
        e1 = _make_event(ocsf_registry, class_uid=3001)
        e2 = _make_event(ocsf_registry, class_uid=3001)
        e3 = _make_event(ocsf_registry, class_uid=3001)
        e1._fields["dst_endpoint.port"] = 80
        e2._fields["dst_endpoint.port"] = 443
        e3._fields["dst_endpoint.port"] = 80  # duplicate
        result = registry.compute_current_value(
            "net_distinct_dst_ports", 3001, [e1, e2, e3]
        )
        assert result == 2.0

    def test_distinct_field_count_none_values_excluded(self, ocsf_registry):
        registry = MetricRegistry(METRICS_PATH)
        e1 = _make_event(ocsf_registry, class_uid=3001)
        e2 = _make_event(ocsf_registry, class_uid=3001)
        e1._fields["dst_endpoint.port"] = 443
        e2._fields["dst_endpoint.port"] = None
        result = registry.compute_current_value(
            "net_distinct_dst_ports", 3001, [e1, e2]
        )
        assert result == 1.0

    def test_sum_field_returns_correct_sum(self, ocsf_registry):
        registry = MetricRegistry(METRICS_PATH)
        e1 = _make_event(ocsf_registry, class_uid=3001)
        e2 = _make_event(ocsf_registry, class_uid=3001)
        e1._fields["network.bytes_out"] = 1000
        e2._fields["network.bytes_out"] = 2000
        result = registry.compute_current_value(
            "net_bytes_out_per_hour", 3001, [e1, e2]
        )
        assert result == 3000.0

    def test_sum_field_none_values_skipped(self, ocsf_registry):
        registry = MetricRegistry(METRICS_PATH)
        e1 = _make_event(ocsf_registry, class_uid=3001)
        e2 = _make_event(ocsf_registry, class_uid=3001)
        e1._fields["network.bytes_out"] = 500
        e2._fields["network.bytes_out"] = None
        result = registry.compute_current_value(
            "net_bytes_out_per_hour", 3001, [e1, e2]
        )
        assert result == 500.0

    def test_sum_field_non_numeric_values_skipped(self, ocsf_registry):
        registry = MetricRegistry(METRICS_PATH)
        e1 = _make_event(ocsf_registry, class_uid=3001)
        e1._fields["network.bytes_out"] = "not_a_number"
        result = registry.compute_current_value(
            "net_bytes_out_per_hour", 3001, [e1]
        )
        assert result == 0.0

    def test_rate_per_hour_single_event_returns_none(self, ocsf_registry):
        registry = MetricRegistry(METRICS_PATH)
        events = [_make_event(ocsf_registry, class_uid=3001)]
        result = registry.compute_current_value(
            "net_connection_count_per_hour", 3001, events
        )
        assert result is None

    def test_rate_per_hour_two_events_correct_rate(self, ocsf_registry):
        registry = MetricRegistry(METRICS_PATH)
        t1 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        t2 = datetime(2026, 1, 1, 1, 0, 0, tzinfo=UTC)  # 1 hour later
        e1 = _make_event(ocsf_registry, class_uid=3001, time=t1)
        e2 = _make_event(ocsf_registry, class_uid=3001, time=t2)
        result = registry.compute_current_value(
            "net_connection_count_per_hour", 3001, [e1, e2]
        )
        # 2 events over 1 hour = 2.0 per hour
        assert result == pytest.approx(2.0)

    def test_rate_per_hour_zero_time_span_returns_none(self, ocsf_registry):
        registry = MetricRegistry(METRICS_PATH)
        t = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        e1 = _make_event(ocsf_registry, class_uid=3001, time=t)
        e2 = _make_event(
            ocsf_registry, class_uid=3001, time=t,
            metadata_original_time="different"
        )
        result = registry.compute_current_value(
            "net_connection_count_per_hour", 3001, [e1, e2]
        )
        assert result is None


# ==============================================================================
# TestComputationHandlersDirect
# ==============================================================================

class TestComputationHandlersDirect:
    """Test each handler function in isolation."""

    def test_compute_count_empty(self):
        assert _compute_count([], None) == 0.0

    def test_compute_count_multiple(self):
        assert _compute_count([object(), object(), object()], None) == 3.0

    def test_compute_distinct_no_target_field_returns_none(self):
        assert _compute_distinct_field_count([], None) is None

    def test_compute_sum_no_target_field_returns_none(self):
        assert _compute_sum_field([], None) is None

    def test_compute_rate_empty_returns_none(self):
        assert _compute_rate_per_hour([], None) is None

    def test_compute_rate_one_event_returns_none(self, ocsf_registry):
        e = _make_event(ocsf_registry, class_uid=3001)
        assert _compute_rate_per_hour([e], None) is None

    def test_compute_rate_no_time_fields_returns_none(self, ocsf_registry):
        e1 = _make_event(ocsf_registry, class_uid=3001)
        e2 = _make_event(ocsf_registry, class_uid=3001)
        e1._fields["time"] = None
        e2._fields["time"] = None
        assert _compute_rate_per_hour([e1, e2], None) is None


# ==============================================================================
# TestMetricDefinitionImmutability
# ==============================================================================

class TestMetricDefinitionImmutability:

    def test_metric_definition_is_frozen(self):
        md = MetricDefinition(
            metric_name="test",
            class_uid=6003,
            entity_type="user",
            entity_field="actor.user.name",
            computation="count",
            target_field=None,
            description="test",
        )
        with pytest.raises((AttributeError, TypeError)):
            md.metric_name = "changed"

    def test_direct_construction_valid(self):
        md = MetricDefinition(
            metric_name="test",
            class_uid=6003,
            entity_type="user",
            entity_field="actor.user.name",
            computation="count",
            target_field=None,
            description="",
        )
        assert md.metric_name == "test"
        assert md.target_field is None

    def test_supported_computations_constant(self):
        assert "count" in SUPPORTED_COMPUTATIONS
        assert "distinct_field_count" in SUPPORTED_COMPUTATIONS
        assert "sum_field" in SUPPORTED_COMPUTATIONS
        assert "rate_per_hour" in SUPPORTED_COMPUTATIONS
        assert len(SUPPORTED_COMPUTATIONS) == 4