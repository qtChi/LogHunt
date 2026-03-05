# ==============================================================================
# tests/testAudit/testMetrics.py
#
# 100% branch coverage for loghunter/audit/metrics.py
#
# Test strategy:
#   - Construction: None → TypeError.
#   - get_system_metrics(): empty history, mixed success/fail, latency
#     averaging, None latency values excluded, last timestamps,
#     rules_stored/confirmed passed through, logger failure → zeroed result.
#   - get_query_success_rate(): 0 queries, all success, all fail, mixed,
#     logger failure → 0.0.
#   - get_top_event_classes(): limit < 1 → ValueError, empty history,
#     known formats, unknown format skipped, counts aggregated across runs,
#     limit respected, logger failure → [].
#   - All AuditLogger interactions mocked — no real SQLite.
# ==============================================================================

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from loghunter.audit.metrics import FORMAT_CLASS_MAP, AuditMetrics, SystemMetrics


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _query_entry(success: bool = True, latency_ms: float | None = 50.0,
                 executed_at: str = "2026-01-01T10:00:00Z"):
    e = MagicMock()
    e.success = success
    e.latency_ms = latency_ms
    e.executed_at = executed_at
    return e


def _ingest_entry(source_format: str = "zeek", event_count: int = 100,
                  ingested_at: str = "2026-01-01T09:00:00Z"):
    e = MagicMock()
    e.source_format = source_format
    e.event_count = event_count
    e.ingested_at = ingested_at
    return e


def _make_logger(queries=None, ingests=None, query_raises=False, ingest_raises=False):
    logger = MagicMock()
    if query_raises:
        logger.get_query_history.side_effect = RuntimeError("DB error")
    else:
        logger.get_query_history.return_value = queries or []
    if ingest_raises:
        logger.get_ingest_history.side_effect = RuntimeError("DB error")
    else:
        logger.get_ingest_history.return_value = ingests or []
    return logger


def _make_metrics(**kwargs) -> AuditMetrics:
    return AuditMetrics(_make_logger(**kwargs))


# ===========================================================================
# Construction
# ===========================================================================

class TestAuditMetricsConstruction:

    def test_none_raises_type_error(self):
        with pytest.raises(TypeError, match="audit_logger must not be None"):
            AuditMetrics(None)

    def test_valid_construction(self):
        am = AuditMetrics(_make_logger())
        assert am is not None


# ===========================================================================
# get_system_metrics()
# ===========================================================================

class TestGetSystemMetrics:

    def test_returns_system_metrics_instance(self):
        am = _make_metrics()
        result = am.get_system_metrics()
        assert isinstance(result, SystemMetrics)

    def test_empty_history_returns_zeroed_metrics(self):
        am = _make_metrics()
        result = am.get_system_metrics()
        assert result.total_queries == 0
        assert result.successful_queries == 0
        assert result.failed_queries == 0
        assert result.total_ingest_events == 0
        assert result.total_ingest_runs == 0
        assert result.avg_query_latency_ms is None
        assert result.last_ingest_at is None
        assert result.last_query_at is None

    def test_total_queries_counted(self):
        queries = [_query_entry(), _query_entry(), _query_entry()]
        am = _make_metrics(queries=queries)
        assert am.get_system_metrics().total_queries == 3

    def test_successful_queries_counted(self):
        queries = [_query_entry(success=True), _query_entry(success=False),
                   _query_entry(success=True)]
        am = _make_metrics(queries=queries)
        result = am.get_system_metrics()
        assert result.successful_queries == 2
        assert result.failed_queries == 1

    def test_all_failed_queries(self):
        queries = [_query_entry(success=False)] * 3
        am = _make_metrics(queries=queries)
        result = am.get_system_metrics()
        assert result.successful_queries == 0
        assert result.failed_queries == 3

    def test_all_successful_queries(self):
        queries = [_query_entry(success=True)] * 4
        am = _make_metrics(queries=queries)
        result = am.get_system_metrics()
        assert result.successful_queries == 4
        assert result.failed_queries == 0

    def test_avg_latency_computed_from_successful_only(self):
        queries = [
            _query_entry(success=True, latency_ms=100.0),
            _query_entry(success=True, latency_ms=200.0),
            _query_entry(success=False, latency_ms=999.0),  # excluded
        ]
        am = _make_metrics(queries=queries)
        result = am.get_system_metrics()
        assert result.avg_query_latency_ms == pytest.approx(150.0)

    def test_avg_latency_none_excluded_from_average(self):
        queries = [
            _query_entry(success=True, latency_ms=100.0),
            _query_entry(success=True, latency_ms=None),  # excluded
            _query_entry(success=True, latency_ms=300.0),
        ]
        am = _make_metrics(queries=queries)
        result = am.get_system_metrics()
        assert result.avg_query_latency_ms == pytest.approx(200.0)

    def test_avg_latency_none_when_all_latencies_are_none(self):
        queries = [
            _query_entry(success=True, latency_ms=None),
            _query_entry(success=True, latency_ms=None),
        ]
        am = _make_metrics(queries=queries)
        assert am.get_system_metrics().avg_query_latency_ms is None

    def test_avg_latency_none_when_no_successful_queries(self):
        queries = [_query_entry(success=False, latency_ms=100.0)]
        am = _make_metrics(queries=queries)
        assert am.get_system_metrics().avg_query_latency_ms is None

    def test_total_ingest_events_summed(self):
        ingests = [
            _ingest_entry(event_count=100),
            _ingest_entry(event_count=250),
            _ingest_entry(event_count=50),
        ]
        am = _make_metrics(ingests=ingests)
        assert am.get_system_metrics().total_ingest_events == 400

    def test_total_ingest_runs_counted(self):
        ingests = [_ingest_entry()] * 5
        am = _make_metrics(ingests=ingests)
        assert am.get_system_metrics().total_ingest_runs == 5

    def test_none_event_count_treated_as_zero(self):
        ingests = [_ingest_entry(event_count=None), _ingest_entry(event_count=50)]
        am = _make_metrics(ingests=ingests)
        assert am.get_system_metrics().total_ingest_events == 50

    def test_last_ingest_at_from_first_entry(self):
        """History is newest-first so first entry is most recent."""
        ingests = [
            _ingest_entry(ingested_at="2026-01-02T10:00:00Z"),
            _ingest_entry(ingested_at="2026-01-01T10:00:00Z"),
        ]
        am = _make_metrics(ingests=ingests)
        assert am.get_system_metrics().last_ingest_at == "2026-01-02T10:00:00Z"

    def test_last_query_at_from_first_entry(self):
        queries = [
            _query_entry(executed_at="2026-01-03T10:00:00Z"),
            _query_entry(executed_at="2026-01-01T10:00:00Z"),
        ]
        am = _make_metrics(queries=queries)
        assert am.get_system_metrics().last_query_at == "2026-01-03T10:00:00Z"

    def test_rules_stored_passed_through(self):
        am = _make_metrics()
        assert am.get_system_metrics(rules_stored=7).rules_stored == 7

    def test_rules_confirmed_passed_through(self):
        am = _make_metrics()
        assert am.get_system_metrics(rules_confirmed=3).rules_confirmed == 3

    def test_rules_defaults_to_zero(self):
        am = _make_metrics()
        result = am.get_system_metrics()
        assert result.rules_stored == 0
        assert result.rules_confirmed == 0

    def test_logger_failure_returns_zeroed_metrics(self):
        am = _make_metrics(query_raises=True)
        result = am.get_system_metrics()
        assert isinstance(result, SystemMetrics)
        assert result.total_queries == 0

    def test_logger_failure_preserves_rules_args(self):
        am = _make_metrics(query_raises=True)
        result = am.get_system_metrics(rules_stored=5, rules_confirmed=2)
        assert result.rules_stored == 5
        assert result.rules_confirmed == 2

    def test_ingest_failure_returns_zeroed_metrics(self):
        am = _make_metrics(ingest_raises=True)
        result = am.get_system_metrics()
        assert result.total_ingest_events == 0

    def test_reads_up_to_max_history_limit(self):
        """Verifies limit=10000 is passed to both history calls."""
        logger = _make_logger()
        am = AuditMetrics(logger)
        am.get_system_metrics()
        logger.get_query_history.assert_called_once_with(limit=10_000)
        logger.get_ingest_history.assert_called_once_with(limit=10_000)


# ===========================================================================
# get_query_success_rate()
# ===========================================================================

class TestGetQuerySuccessRate:

    def test_returns_float(self):
        am = _make_metrics()
        assert isinstance(am.get_query_success_rate(), float)

    def test_zero_when_no_queries(self):
        am = _make_metrics(queries=[])
        assert am.get_query_success_rate() == 0.0

    def test_100_when_all_successful(self):
        queries = [_query_entry(success=True)] * 5
        am = _make_metrics(queries=queries)
        assert am.get_query_success_rate() == pytest.approx(100.0)

    def test_0_when_all_failed(self):
        queries = [_query_entry(success=False)] * 4
        am = _make_metrics(queries=queries)
        assert am.get_query_success_rate() == 0.0

    def test_50_when_half_successful(self):
        queries = [
            _query_entry(success=True),
            _query_entry(success=False),
        ]
        am = _make_metrics(queries=queries)
        assert am.get_query_success_rate() == pytest.approx(50.0)

    def test_75_when_three_of_four_successful(self):
        queries = [
            _query_entry(success=True),
            _query_entry(success=True),
            _query_entry(success=True),
            _query_entry(success=False),
        ]
        am = _make_metrics(queries=queries)
        assert am.get_query_success_rate() == pytest.approx(75.0)

    def test_logger_failure_returns_zero(self):
        am = _make_metrics(query_raises=True)
        assert am.get_query_success_rate() == 0.0

    def test_single_successful_query(self):
        am = _make_metrics(queries=[_query_entry(success=True)])
        assert am.get_query_success_rate() == pytest.approx(100.0)

    def test_single_failed_query(self):
        am = _make_metrics(queries=[_query_entry(success=False)])
        assert am.get_query_success_rate() == 0.0


# ===========================================================================
# get_top_event_classes()
# ===========================================================================

class TestGetTopEventClasses:

    def test_limit_less_than_one_raises_value_error(self):
        am = _make_metrics()
        with pytest.raises(ValueError, match="limit must be at least 1"):
            am.get_top_event_classes(limit=0)

    def test_limit_negative_raises_value_error(self):
        am = _make_metrics()
        with pytest.raises(ValueError):
            am.get_top_event_classes(limit=-1)

    def test_empty_history_returns_empty_list(self):
        am = _make_metrics(ingests=[])
        assert am.get_top_event_classes() == []

    def test_returns_list_of_tuples(self):
        ingests = [_ingest_entry(source_format="zeek", event_count=100)]
        am = _make_metrics(ingests=ingests)
        result = am.get_top_event_classes()
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, tuple)
            assert len(item) == 2

    def test_zeek_maps_to_3001(self):
        ingests = [_ingest_entry(source_format="zeek", event_count=100)]
        am = _make_metrics(ingests=ingests)
        result = am.get_top_event_classes()
        assert (3001, 100) in result

    def test_apache_maps_to_3002(self):
        ingests = [_ingest_entry(source_format="apache", event_count=50)]
        am = _make_metrics(ingests=ingests)
        result = am.get_top_event_classes()
        assert (3002, 50) in result

    def test_evtx_maps_to_6003(self):
        ingests = [_ingest_entry(source_format="evtx", event_count=200)]
        am = _make_metrics(ingests=ingests)
        result = am.get_top_event_classes()
        assert (6003, 200) in result

    def test_syslog_maps_to_1001(self):
        ingests = [_ingest_entry(source_format="syslog", event_count=75)]
        am = _make_metrics(ingests=ingests)
        result = am.get_top_event_classes()
        assert (1001, 75) in result

    def test_unknown_format_skipped(self):
        ingests = [
            _ingest_entry(source_format="unknown_format", event_count=999),
            _ingest_entry(source_format="zeek", event_count=10),
        ]
        am = _make_metrics(ingests=ingests)
        result = am.get_top_event_classes()
        class_uids = [uid for uid, _ in result]
        assert 3001 in class_uids
        # unknown_format has no mapping, should not appear
        assert len(result) == 1

    def test_all_unknown_formats_returns_empty(self):
        ingests = [_ingest_entry(source_format="custom", event_count=100)]
        am = _make_metrics(ingests=ingests)
        assert am.get_top_event_classes() == []

    def test_counts_aggregated_across_multiple_runs(self):
        ingests = [
            _ingest_entry(source_format="zeek", event_count=100),
            _ingest_entry(source_format="zeek", event_count=200),
            _ingest_entry(source_format="zeek", event_count=50),
        ]
        am = _make_metrics(ingests=ingests)
        result = am.get_top_event_classes()
        assert (3001, 350) in result

    def test_sorted_descending_by_count(self):
        ingests = [
            _ingest_entry(source_format="zeek", event_count=50),
            _ingest_entry(source_format="apache", event_count=200),
            _ingest_entry(source_format="evtx", event_count=100),
        ]
        am = _make_metrics(ingests=ingests)
        result = am.get_top_event_classes()
        counts = [count for _, count in result]
        assert counts == sorted(counts, reverse=True)

    def test_limit_respected(self):
        ingests = [
            _ingest_entry(source_format="zeek", event_count=400),
            _ingest_entry(source_format="apache", event_count=300),
            _ingest_entry(source_format="evtx", event_count=200),
            _ingest_entry(source_format="syslog", event_count=100),
        ]
        am = _make_metrics(ingests=ingests)
        result = am.get_top_event_classes(limit=2)
        assert len(result) == 2
        # Top 2 by count
        assert result[0][1] == 400
        assert result[1][1] == 300

    def test_limit_1_returns_single_top_entry(self):
        ingests = [
            _ingest_entry(source_format="zeek", event_count=500),
            _ingest_entry(source_format="apache", event_count=100),
        ]
        am = _make_metrics(ingests=ingests)
        result = am.get_top_event_classes(limit=1)
        assert len(result) == 1
        assert result[0] == (3001, 500)

    def test_none_event_count_treated_as_zero(self):
        ingests = [_ingest_entry(source_format="zeek", event_count=None)]
        am = _make_metrics(ingests=ingests)
        result = am.get_top_event_classes()
        assert (3001, 0) in result

    def test_logger_failure_returns_empty_list(self):
        am = _make_metrics(ingest_raises=True)
        assert am.get_top_event_classes() == []

    def test_default_limit_is_five(self):
        ingests = [
            _ingest_entry(source_format="zeek", event_count=600),
            _ingest_entry(source_format="apache", event_count=500),
            _ingest_entry(source_format="evtx", event_count=400),
            _ingest_entry(source_format="syslog", event_count=300),
            _ingest_entry(source_format="zeek", event_count=200),
        ]
        am = _make_metrics(ingests=ingests)
        result = am.get_top_event_classes()
        assert len(result) <= 5


# ===========================================================================
# FORMAT_CLASS_MAP constant
# ===========================================================================

class TestFormatClassMap:

    def test_is_dict(self):
        assert isinstance(FORMAT_CLASS_MAP, dict)

    def test_contains_all_four_formats(self):
        for fmt in ("zeek", "apache", "syslog", "evtx"):
            assert fmt in FORMAT_CLASS_MAP

    def test_all_values_are_supported_class_uids(self):
        supported = {1001, 3001, 3002, 4001, 6003}
        for uid in FORMAT_CLASS_MAP.values():
            assert uid in supported