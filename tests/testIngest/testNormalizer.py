# ==============================================================================
# tests/testIngest/testNormalizer.py
#
# Tests for loghunter/ingest/normalizer.py
#
# Coverage strategy — every branch explicitly targeted:
#
# Constructor:
#   None registry → TypeError
#   None mitre_mapper → TypeError
#   None audit_logger → TypeError
#   Valid args → constructs
#
# register_mapping:
#   None source_format → TypeError
#   None class_uid → TypeError
#   None field_map → TypeError
#   Empty field_map → ValueError
#   Duplicate (format, class_uid) → ValueError
#   Valid registration → stored
#
# normalize:
#   None raw_dict → TypeError
#   None source_format → TypeError
#   Unregistered format → UnregisteredFormatError
#   Unknown raw field (not in map) → silently dropped
#   Mapped field not in registry → dropped + audit logged
#   Valid dict → OCSFEvent returned
#   MitreMapper techniques set on event
#   mitre_technique_ids not registered for class → not set
#
# normalize_batch:
#   None raw_dicts → TypeError
#   Empty list → ([], []) + ingest logged
#   All succeed → all in successes
#   All fail → all in failures
#   Mixed → split correctly
#   Ingest audit always logged
#
# _coerce_time:
#   None → datetime.now(UTC)
#   tz-aware datetime → returned as-is
#   naive datetime → UTC attached
#   Unix timestamp float → converted
#   Unix timestamp string → converted
#   ISO 8601 string → converted
#   ISO 8601 string naive → UTC attached
#   Unparseable → datetime.now(UTC)
#
# _coerce_int:
#   bool value → ValueError
#   int value → returned
#   None → ValueError
#   string int → converted
#   non-numeric string → ValueError
# ==============================================================================

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

from loghunter.audit.logger import AuditLogger
from loghunter.engine.mitre_mapper import MitreMapper
from loghunter.engine.sqlite_layer import SQLiteLayer
from loghunter.exceptions import UnregisteredFormatError
from loghunter.ingest.normalizer import OCSFNormalizer
from loghunter.schema.ocsf_event import OCSFEvent

UTC = timezone.utc
T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)

# ---------------------------------------------------------------------------
# Minimal valid field map for zeek_conn → class 3001
# ---------------------------------------------------------------------------
_ZEEK_MAP = {
    "ts":          "time",
    "id.orig_h":   "src_endpoint.ip",
    "id.orig_p":   "src_endpoint.port",
    "id.resp_h":   "dst_endpoint.ip",
    "id.resp_p":   "dst_endpoint.port",
    "proto":       "network.protocol",
    "orig_bytes":  "network.bytes_out",
    # Required OCSF fields mapped via constants
    "_class_uid":           "class_uid",
    "_activity_id":         "activity_id",
    "_severity_id":         "severity_id",
    "_log_source":          "metadata.log_source",
    "_original_time":       "metadata.original_time",
}

_VALID_ZEEK_RAW = {
    "ts": "1609459200.0",
    "id.orig_h": "192.168.1.1",
    "id.orig_p": "54321",
    "id.resp_h": "8.8.8.8",
    "id.resp_p": "443",
    "proto": "tcp",
    "orig_bytes": "512",
    "_class_uid": 3001,
    "_activity_id": 1,
    "_severity_id": 1,
    "_log_source": "zeek",
    "_original_time": "2021-01-01T00:00:00Z",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_layer(tmp_path):
    return SQLiteLayer(str(tmp_path / "test.db"))


def _make_normalizer(tmp_path, ocsf_registry):
    layer = _make_layer(tmp_path)
    audit = AuditLogger(layer)
    mapper = MitreMapper()
    norm = OCSFNormalizer(ocsf_registry, mapper, audit)
    return norm, layer


def _register_zeek(norm):
    norm.register_mapping("zeek_conn", 3001, _ZEEK_MAP)


# ==============================================================================
# TestConstructor
# ==============================================================================

class TestConstructor:

    def test_none_registry_raises_type_error(self, tmp_path, ocsf_registry):
        layer = _make_layer(tmp_path)
        audit = AuditLogger(layer)
        with pytest.raises(TypeError, match="registry"):
            OCSFNormalizer(None, MitreMapper(), audit)
        layer.close()

    def test_none_mitre_mapper_raises_type_error(self, tmp_path, ocsf_registry):
        layer = _make_layer(tmp_path)
        audit = AuditLogger(layer)
        with pytest.raises(TypeError, match="mitre_mapper"):
            OCSFNormalizer(ocsf_registry, None, audit)
        layer.close()

    def test_none_audit_logger_raises_type_error(self, tmp_path, ocsf_registry):
        with pytest.raises(TypeError, match="audit_logger"):
            OCSFNormalizer(ocsf_registry, MitreMapper(), None)

    def test_valid_construction(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        assert norm is not None
        layer.close()


# ==============================================================================
# TestRegisterMapping
# ==============================================================================

class TestRegisterMapping:

    def test_none_source_format_raises_type_error(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        with pytest.raises(TypeError, match="source_format"):
            norm.register_mapping(None, 3001, {"a": "b"})
        layer.close()

    def test_none_class_uid_raises_type_error(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        with pytest.raises(TypeError, match="class_uid"):
            norm.register_mapping("zeek_conn", None, {"a": "b"})
        layer.close()

    def test_none_field_map_raises_type_error(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        with pytest.raises(TypeError, match="field_map"):
            norm.register_mapping("zeek_conn", 3001, None)
        layer.close()

    def test_empty_field_map_raises_value_error(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        with pytest.raises(ValueError):
            norm.register_mapping("zeek_conn", 3001, {})
        layer.close()

    def test_duplicate_registration_raises_value_error(
        self, tmp_path, ocsf_registry
    ):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        _register_zeek(norm)
        with pytest.raises(ValueError, match="already registered"):
            _register_zeek(norm)
        layer.close()

    def test_same_format_different_class_is_valid(
        self, tmp_path, ocsf_registry
    ):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        norm.register_mapping("zeek_conn", 3001, _ZEEK_MAP)
        norm.register_mapping("zeek_conn", 3002, _ZEEK_MAP)
        assert ("zeek_conn", 3001) in norm._mappings
        assert ("zeek_conn", 3002) in norm._mappings
        layer.close()

    def test_valid_registration_stored(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        _register_zeek(norm)
        assert ("zeek_conn", 3001) in norm._mappings
        layer.close()

    def test_stored_mapping_is_copy(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        original = dict(_ZEEK_MAP)
        norm.register_mapping("zeek_conn", 3001, original)
        original["injected"] = "field"
        assert "injected" not in norm._mappings[("zeek_conn", 3001)]
        layer.close()


# ==============================================================================
# TestNormalize
# ==============================================================================

class TestNormalize:

    def test_none_raw_dict_raises_type_error(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        _register_zeek(norm)
        with pytest.raises(TypeError, match="raw_dict"):
            norm.normalize(None, "zeek_conn", 3001)
        layer.close()

    def test_none_source_format_raises_type_error(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        with pytest.raises(TypeError, match="source_format"):
            norm.normalize({}, None, 3001)
        layer.close()

    def test_unregistered_format_raises_unregistered_format_error(
        self, tmp_path, ocsf_registry
    ):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        with pytest.raises(UnregisteredFormatError):
            norm.normalize({}, "no_such_format", 3001)
        layer.close()

    def test_unregistered_error_is_also_value_error(
        self, tmp_path, ocsf_registry
    ):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        with pytest.raises(ValueError):
            norm.normalize({}, "no_such_format", 3001)
        layer.close()

    def test_valid_raw_dict_returns_ocsf_event(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        _register_zeek(norm)
        event = norm.normalize(_VALID_ZEEK_RAW.copy(), "zeek_conn", 3001)
        assert isinstance(event, OCSFEvent)
        layer.close()

    def test_event_has_correct_class_uid(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        _register_zeek(norm)
        event = norm.normalize(_VALID_ZEEK_RAW.copy(), "zeek_conn", 3001)
        assert event.get_class_uid() == 3001
        layer.close()

    def test_unknown_raw_field_silently_dropped(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        _register_zeek(norm)
        raw = dict(_VALID_ZEEK_RAW)
        raw["unknown_zeek_field"] = "should_be_dropped"
        # Must not raise
        event = norm.normalize(raw, "zeek_conn", 3001)
        assert isinstance(event, OCSFEvent)
        layer.close()

    def test_mapped_field_not_in_registry_dropped_and_audit_logged(
        self, tmp_path, ocsf_registry
    ):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        # Map a raw field to an OCSF path that is not valid for class 3001
        bad_map = dict(_ZEEK_MAP)
        bad_map["bad_raw"] = "actor.user.name"  # not valid for 3001
        norm.register_mapping("zeek_conn_bad", 3001, bad_map)
        raw = dict(_VALID_ZEEK_RAW)
        raw["bad_raw"] = "should_drop"
        event = norm.normalize(raw, "zeek_conn_bad", 3001)
        assert isinstance(event, OCSFEvent)
        # Verify audit was called — check query_audit table
        rows = layer.execute_read(
            "SELECT * FROM query_audit WHERE event_class = ?", (3001,)
        )
        assert len(rows) > 0
        layer.close()

    def test_mitre_techniques_set_on_event(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        _register_zeek(norm)
        # Port 443 → T1071
        raw = dict(_VALID_ZEEK_RAW)
        raw["id.resp_p"] = 443
        event = norm.normalize(raw, "zeek_conn", 3001)
        techniques = event.get_field("mitre_technique_ids")
        assert techniques is not None
        assert "T1071" in techniques
        layer.close()

    def test_empty_raw_dict_raises_on_missing_required_fields(
        self, tmp_path, ocsf_registry
    ):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        _register_zeek(norm)
        with pytest.raises((ValueError, TypeError)):
            norm.normalize({}, "zeek_conn", 3001)
        layer.close()


# ==============================================================================
# TestNormalizeBatch
# ==============================================================================

class TestNormalizeBatch:

    def test_none_raw_dicts_raises_type_error(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        _register_zeek(norm)
        with pytest.raises(TypeError):
            norm.normalize_batch(None, "zeek_conn", 3001)
        layer.close()

    def test_empty_list_returns_empty_tuples(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        _register_zeek(norm)
        successes, failures = norm.normalize_batch([], "zeek_conn", 3001)
        assert successes == []
        assert failures == []
        layer.close()

    def test_empty_list_still_logs_ingest_audit(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        _register_zeek(norm)
        norm.normalize_batch([], "zeek_conn", 3001)
        rows = layer.execute_read("SELECT * FROM ingest_audit", ())
        assert len(rows) == 1
        assert rows[0]["event_count"] == 0
        layer.close()

    def test_all_valid_returns_all_in_successes(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        _register_zeek(norm)
        raws = [dict(_VALID_ZEEK_RAW) for _ in range(3)]
        successes, failures = norm.normalize_batch(raws, "zeek_conn", 3001)
        assert len(successes) == 3
        assert failures == []
        layer.close()

    def test_all_invalid_returns_all_in_failures(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        _register_zeek(norm)
        raws = [{} for _ in range(3)]
        successes, failures = norm.normalize_batch(raws, "zeek_conn", 3001)
        assert successes == []
        assert len(failures) == 3
        layer.close()

    def test_mixed_split_correctly(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        _register_zeek(norm)
        raws = [
            dict(_VALID_ZEEK_RAW),
            {},
            dict(_VALID_ZEEK_RAW),
            {},
        ]
        successes, failures = norm.normalize_batch(raws, "zeek_conn", 3001)
        assert len(successes) == 2
        assert len(failures) == 2
        layer.close()

    def test_ingest_audit_logged_with_correct_counts(
        self, tmp_path, ocsf_registry
    ):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        _register_zeek(norm)
        raws = [dict(_VALID_ZEEK_RAW), {}]
        norm.normalize_batch(raws, "zeek_conn", 3001)
        rows = layer.execute_read("SELECT * FROM ingest_audit", ())
        assert rows[0]["event_count"] == 1
        assert rows[0]["failed_count"] == 1
        assert rows[0]["source_format"] == "zeek_conn"
        layer.close()

    def test_returns_tuple(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        _register_zeek(norm)
        result = norm.normalize_batch([], "zeek_conn", 3001)
        assert isinstance(result, tuple)
        assert len(result) == 2
        layer.close()

    def test_never_raises_on_bad_format(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        # unregistered format — each call fails, batch handles it
        raws = [dict(_VALID_ZEEK_RAW)]
        successes, failures = norm.normalize_batch(
            raws, "unregistered_format", 3001
        )
        assert successes == []
        assert len(failures) == 1
        layer.close()


# ==============================================================================
# TestCoerceTime
# ==============================================================================

class TestCoerceTime:

    def _norm(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        return norm, layer

    def test_none_returns_datetime(self, tmp_path, ocsf_registry):
        norm, layer = self._norm(tmp_path, ocsf_registry)
        result = norm._coerce_time(None)
        assert isinstance(result, datetime)
        assert result.tzinfo is not None
        layer.close()

    def test_tz_aware_datetime_returned_as_is(self, tmp_path, ocsf_registry):
        norm, layer = self._norm(tmp_path, ocsf_registry)
        result = norm._coerce_time(T0)
        assert result == T0
        layer.close()

    def test_naive_datetime_gets_utc(self, tmp_path, ocsf_registry):
        norm, layer = self._norm(tmp_path, ocsf_registry)
        naive = datetime(2026, 1, 1)
        result = norm._coerce_time(naive)
        assert result.tzinfo is not None
        layer.close()

    def test_unix_timestamp_float(self, tmp_path, ocsf_registry):
        norm, layer = self._norm(tmp_path, ocsf_registry)
        result = norm._coerce_time(1609459200.0)
        assert isinstance(result, datetime)
        assert result.year == 2021
        layer.close()

    def test_unix_timestamp_string(self, tmp_path, ocsf_registry):
        norm, layer = self._norm(tmp_path, ocsf_registry)
        result = norm._coerce_time("1609459200.0")
        assert isinstance(result, datetime)
        assert result.year == 2021
        layer.close()

    def test_iso_8601_string(self, tmp_path, ocsf_registry):
        norm, layer = self._norm(tmp_path, ocsf_registry)
        result = norm._coerce_time("2026-01-01T00:00:00+00:00")
        assert isinstance(result, datetime)
        assert result.year == 2026
        layer.close()

    def test_iso_8601_naive_string_gets_utc(self, tmp_path, ocsf_registry):
        norm, layer = self._norm(tmp_path, ocsf_registry)
        result = norm._coerce_time("2026-01-01T00:00:00")
        assert result.tzinfo is not None
        layer.close()

    def test_unparseable_returns_now(self, tmp_path, ocsf_registry):
        norm, layer = self._norm(tmp_path, ocsf_registry)
        result = norm._coerce_time("not-a-date-at-all")
        assert isinstance(result, datetime)
        assert result.tzinfo is not None
        layer.close()


# ==============================================================================
# TestCoerceInt
# ==============================================================================

class TestCoerceInt:

    def _norm(self, tmp_path, ocsf_registry):
        norm, layer = _make_normalizer(tmp_path, ocsf_registry)
        return norm, layer

    def test_int_returned_directly(self, tmp_path, ocsf_registry):
        norm, layer = self._norm(tmp_path, ocsf_registry)
        assert norm._coerce_int(5, "field") == 5
        layer.close()

    def test_bool_raises_value_error(self, tmp_path, ocsf_registry):
        norm, layer = self._norm(tmp_path, ocsf_registry)
        with pytest.raises(ValueError, match="bool"):
            norm._coerce_int(True, "field")
        layer.close()

    def test_false_bool_raises_value_error(self, tmp_path, ocsf_registry):
        norm, layer = self._norm(tmp_path, ocsf_registry)
        with pytest.raises(ValueError, match="bool"):
            norm._coerce_int(False, "field")
        layer.close()

    def test_none_raises_value_error(self, tmp_path, ocsf_registry):
        norm, layer = self._norm(tmp_path, ocsf_registry)
        with pytest.raises(ValueError, match="missing"):
            norm._coerce_int(None, "activity_id")
        layer.close()

    def test_string_int_converted(self, tmp_path, ocsf_registry):
        norm, layer = self._norm(tmp_path, ocsf_registry)
        assert norm._coerce_int("3", "severity_id") == 3
        layer.close()

    def test_non_numeric_string_raises_value_error(
        self, tmp_path, ocsf_registry
    ):
        norm, layer = self._norm(tmp_path, ocsf_registry)
        with pytest.raises(ValueError, match="cannot be coerced"):
            norm._coerce_int("not_an_int", "field")
        layer.close()

    def test_float_string_raises_value_error(self, tmp_path, ocsf_registry):
        # "1.5" cannot be coerced to int via int()
        norm, layer = self._norm(tmp_path, ocsf_registry)
        with pytest.raises(ValueError):
            norm._coerce_int("1.5", "field")
        layer.close()